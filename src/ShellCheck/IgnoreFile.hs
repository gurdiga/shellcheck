{-
    Copyright 2012-2024 Vidar Holen

    This file is part of ShellCheck.
    https://www.shellcheck.net

    ShellCheck is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ShellCheck is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
-}

{-# LANGUAGE TemplateHaskell #-}
-- Parsing and matching of .shellcheckignore files, which use the pattern
-- syntax of gitignore(5).
module ShellCheck.IgnoreFile (IgnorePattern, parseIgnoreFile, isIgnored, runTests) where

import Data.Char
import Data.List
import Data.Maybe

import ShellCheck.Regex (matches)

import Test.QuickCheck
import Text.Regex.TDFA (CompOption(..), Regex, defaultCompOpt, defaultExecOpt, makeRegexOpts)

data IgnorePattern = IgnorePattern {
    negated :: Bool,
    regex :: Regex
}

prop_parseBlankLines = null $ parseIgnoreFile "\n\n   \n\t\n"
prop_parseComments = null $ parseIgnoreFile "# foo\n#bar\n"
prop_parseCountsPatterns = length (parseIgnoreFile "a\n\n#c\n!b\n") == 2
prop_parseEmptyPatterns = null $ parseIgnoreFile "!\n/\n!/\n"
prop_parseCrlfBlankAndComment = null $ parseIgnoreFile "\r\n# c\r\n"
prop_parseNoFinalNewline = ignoreVerdict "foo.sh" "foo.sh" == Just True
prop_parseCrlf1 = ignoreVerdict "foo.sh\r\nbar.sh\r\n" "foo.sh" == Just True
prop_parseCrlf2 = ignoreVerdict "foo.sh\r\nbar.sh\r\n" "bar.sh" == Just True
prop_parseCrlfEscapedSpace = ignoreVerdict "foo\\ \r\n" "foo " == Just True
prop_parseEscapedHash = ignoreVerdict "\\#foo\n" "#foo" == Just True
prop_parseEscapedBang1 = ignoreVerdict "\\!foo\n" "!foo" == Just True
prop_parseEscapedBang2 = ignoreVerdict "\\!foo\n" "foo" == Nothing
prop_parseTrailingSpace = ignoreVerdict "foo.sh  \t\n" "foo.sh" == Just True
prop_parseEscapedTrailingSpace1 = ignoreVerdict "foo\\ \n" "foo " == Just True
prop_parseEscapedTrailingSpace2 = ignoreVerdict "foo\\ \n" "foo" == Nothing
prop_parseEscapedThenPlainSpace = ignoreVerdict "foo\\  \n" "foo " == Just True
prop_parseLeadingSpace = ignoreVerdict " foo\n" "foo" == Nothing
parseIgnoreFile :: String -> [IgnorePattern]
parseIgnoreFile = mapMaybe parseLine . lines

prop_isIgnoredEmpty = ignoreVerdict "" "foo.sh" == Nothing
prop_isIgnoredNoMatch = ignoreVerdict "foo.sh\n" "bar.sh" == Nothing
prop_isIgnoredMatch = ignoreVerdict "foo.sh\n" "foo.sh" == Just True
prop_isIgnoredNegation = ignoreVerdict "*.sh\n!keep.sh\n" "keep.sh" == Just False
prop_isIgnoredNegationOther = ignoreVerdict "*.sh\n!keep.sh\n" "drop.sh" == Just True
prop_isIgnoredNegationFirst = ignoreVerdict "!keep.sh\n*.sh\n" "keep.sh" == Just True
prop_isIgnoredNegationUnmatched = ignoreVerdict "!keep.sh\n" "other.sh" == Nothing
prop_isIgnoredNegationOnly = ignoreVerdict "!keep.sh\n" "keep.sh" == Just False
prop_isIgnoredLastWins = ignoreVerdict "*.sh\n!keep.sh\nkeep.sh\n" "keep.sh" == Just True
prop_isIgnoredReincludeInDir1 = ignoreVerdict "vendor/\n!vendor/keep.sh\n" "vendor/keep.sh" == Just False
prop_isIgnoredReincludeInDir2 = ignoreVerdict "vendor/\n!vendor/keep.sh\n" "vendor/drop.sh" == Just True
-- Unlike git, a '!' pattern can re-include a file whose parent directory was
-- excluded: directories are never traversed, only file paths are seen.
isIgnored :: [IgnorePattern] -> FilePath -> Maybe Bool
isIgnored patterns path = foldl' decide Nothing patterns
  where
    decide previous ignorePattern
        | path `matches` regex ignorePattern = Just . not $ negated ignorePattern
        | otherwise = previous

parseLine :: String -> Maybe IgnorePattern
parseLine line =
    case stripTrailingSpace line of
        '#':_ -> Nothing
        '!':rest -> IgnorePattern True <$> patternRegex rest
        rest -> IgnorePattern False <$> patternRegex rest

stripTrailingSpace :: String -> String
stripTrailingSpace ('\\':c:rest) = '\\' : c : stripTrailingSpace rest
stripTrailingSpace s | all isSpace s = ""
stripTrailingSpace (c:rest) = c : stripTrailingSpace rest

prop_anyDepth1 = ignoreVerdict "foo.sh\n" "a/b/foo.sh" == Just True
prop_anyDepth2 = ignoreVerdict "*.sh\n" "a/b/c.sh" == Just True
prop_anyDepthWholeName = ignoreVerdict "foo.sh\n" "a/xfoo.sh" == Nothing
prop_anchoredLeading1 = ignoreVerdict "/foo.sh\n" "foo.sh" == Just True
prop_anchoredLeading2 = ignoreVerdict "/foo.sh\n" "a/foo.sh" == Nothing
prop_anchoredInterior1 = ignoreVerdict "a/foo.sh\n" "a/foo.sh" == Just True
prop_anchoredInterior2 = ignoreVerdict "a/foo.sh\n" "x/a/foo.sh" == Nothing
prop_dirOnly1 = ignoreVerdict "build/\n" "build/a.sh" == Just True
prop_dirOnly2 = ignoreVerdict "build/\n" "x/build/y/a.sh" == Just True
prop_dirOnlyFile1 = ignoreVerdict "build/\n" "build" == Nothing
prop_dirOnlyFile2 = ignoreVerdict "build/\n" "x/build" == Nothing
prop_dirOnlyWholeName = ignoreVerdict "build/\n" "abuild/a.sh" == Nothing
prop_dirOnlyAnchored1 = ignoreVerdict "/build/\n" "build/a.sh" == Just True
prop_dirOnlyAnchored2 = ignoreVerdict "/build/\n" "x/build/a.sh" == Nothing
prop_dirOnlyInterior1 = ignoreVerdict "a/b/\n" "a/b/c.sh" == Just True
prop_dirOnlyInterior2 = ignoreVerdict "a/b/\n" "x/a/b/c.sh" == Nothing
prop_dirOnlyInteriorFile = ignoreVerdict "a/b/\n" "a/b" == Nothing
prop_dirPrefix1 = ignoreVerdict "vendor\n" "vendor/a/b.sh" == Just True
prop_dirPrefix2 = ignoreVerdict "vendor\n" "x/vendor/a.sh" == Just True
prop_dirPrefixFile = ignoreVerdict "vendor\n" "vendor" == Just True
prop_dirPrefixWholeName = ignoreVerdict "vendor\n" "vendored/a.sh" == Nothing
prop_dirPrefixAnchored1 = ignoreVerdict "/vendor\n" "vendor/a.sh" == Just True
prop_dirPrefixAnchored2 = ignoreVerdict "/vendor\n" "x/vendor/a.sh" == Nothing
prop_dirPrefixGlob = ignoreVerdict "*.d\n" "conf.d/a.sh" == Just True
patternRegex :: String -> Maybe Regex
patternRegex pattern
    | null body = Nothing
    | otherwise = Just . compile $
        "^" ++ depthPrefix ++ segmentsRegex (splitSegments body) ++ treeSuffix ++ "$"
  where
    dirOnly = "/" `isSuffixOf` pattern
    trimmed = if dirOnly then init pattern else pattern
    anchored = '/' `elem` trimmed
    body = fromMaybe trimmed $ stripPrefix "/" trimmed
    depthPrefix = if anchored then "" else "(.*/)?"
    treeSuffix = if dirOnly then "/.*" else "(/.*)?"

prop_newlineInNameAnchor = ignoreVerdict "/foo\n" "x\nfoo" == Nothing
prop_newlineInNameWildcard = ignoreVerdict "*.sh\n" "a\nb.sh" == Just True
prop_newlineInNameDir = ignoreVerdict "vendor\n" "vendor/a\nb.sh" == Just True
-- Not ShellCheck.Regex.mkRegex: regex-tdfa is multiline by default, where
-- '^' and '$' also match around a newline inside a file name, and '.' and
-- negated classes don't match one.
compile :: String -> Regex
compile = makeRegexOpts defaultCompOpt { multiline = False } defaultExecOpt

-- An escaped '/' stays inside its segment, like any other escaped character.
splitSegments :: String -> [String]
splitSegments = go ""
  where
    go acc ('\\':c:rest) = go (c:'\\':acc) rest
    go acc ('/':rest) = reverse acc : go "" rest
    go acc (c:rest) = go (c:acc) rest
    go acc [] = [reverse acc]

prop_doubleStarPrefix1 = ignoreVerdict "**/foo.sh\n" "foo.sh" == Just True
prop_doubleStarPrefix2 = ignoreVerdict "**/foo.sh\n" "a/b/foo.sh" == Just True
prop_doubleStarPrefix3 = ignoreVerdict "**/a/foo.sh\n" "x/y/a/foo.sh" == Just True
prop_doubleStarPrefix4 = ignoreVerdict "**/a/foo.sh\n" "x/a/y/foo.sh" == Nothing
prop_doubleStarSuffix1 = ignoreVerdict "a/**\n" "a/b/c.sh" == Just True
prop_doubleStarSuffix2 = ignoreVerdict "a/**\n" "a" == Nothing
prop_doubleStarSuffix3 = ignoreVerdict "a/**\n" "x/a/b.sh" == Nothing
prop_doubleStarInterior1 = ignoreVerdict "a/**/b.sh\n" "a/b.sh" == Just True
prop_doubleStarInterior2 = ignoreVerdict "a/**/b.sh\n" "a/x/y/b.sh" == Just True
prop_doubleStarInterior3 = ignoreVerdict "a/**/b.sh\n" "ab.sh" == Nothing
prop_doubleStarInterior4 = ignoreVerdict "a/**/b.sh\n" "a/x/c.sh" == Nothing
prop_doubleStarRepeated = ignoreVerdict "a/**/**/b.sh\n" "a/b.sh" == Just True
prop_doubleStarAlone = ignoreVerdict "**\n" "a/b.sh" == Just True
prop_doubleStarInSegment1 = ignoreVerdict "a/**b\n" "a/xb" == Just True
prop_doubleStarInSegment2 = ignoreVerdict "a/**b\n" "a/x/b" == Nothing
segmentsRegex :: [String] -> String
segmentsRegex ["**"] = ".*"
segmentsRegex ("**":rest) = "(.*/)?" ++ segmentsRegex rest
segmentsRegex [segment] = segmentRegex segment
segmentsRegex (segment:rest) = segmentRegex segment ++ "/" ++ segmentsRegex rest
segmentsRegex [] = ""

prop_star1 = ignoreVerdict "foo*.sh\n" "foobar.sh" == Just True
prop_starEmpty = ignoreVerdict "foo*.sh\n" "foo.sh" == Just True
prop_starNoSlash1 = ignoreVerdict "/*.sh\n" "a/b.sh" == Nothing
prop_starNoSlash2 = ignoreVerdict "a/*.sh\n" "a/b/c.sh" == Nothing
prop_starSegment = ignoreVerdict "a/*/c.sh\n" "a/b/c.sh" == Just True
prop_question1 = ignoreVerdict "fo?.sh\n" "foo.sh" == Just True
prop_question2 = ignoreVerdict "fo?.sh\n" "fo.sh" == Nothing
prop_questionNoSlash = ignoreVerdict "a?b\n" "a/b" == Nothing
prop_escapedStar1 = ignoreVerdict "foo\\*.sh\n" "foo*.sh" == Just True
prop_escapedStar2 = ignoreVerdict "foo\\*.sh\n" "fooo.sh" == Nothing
prop_escapedQuestion1 = ignoreVerdict "foo\\?\n" "foo?" == Just True
prop_escapedQuestion2 = ignoreVerdict "foo\\?\n" "fooo" == Nothing
prop_escapedBracket1 = ignoreVerdict "\\[a]\n" "[a]" == Just True
prop_escapedBracket2 = ignoreVerdict "\\[a]\n" "a" == Nothing
prop_escapedBackslash = ignoreVerdict "a\\\\b\n" "a\\b" == Just True
prop_escapedPlain = ignoreVerdict "\\a\\b\n" "ab" == Just True
prop_trailingBackslash = ignoreVerdict "a\\\n" "a\\" == Just True
prop_regexDot1 = ignoreVerdict "a.sh\n" "a.sh" == Just True
prop_regexDot2 = ignoreVerdict "a.sh\n" "axsh" == Nothing
prop_regexPlus1 = ignoreVerdict "a+b\n" "a+b" == Just True
prop_regexPlus2 = ignoreVerdict "a+b\n" "aab" == Nothing
prop_regexGroup1 = ignoreVerdict "(a|b)\n" "(a|b)" == Just True
prop_regexGroup2 = ignoreVerdict "(a|b)\n" "a" == Nothing
prop_regexDollar = ignoreVerdict "a$b\n" "a$b" == Just True
prop_regexCaret = ignoreVerdict "a^b\n" "a^b" == Just True
prop_regexBrace1 = ignoreVerdict "a{2}\n" "a{2}" == Just True
prop_regexBrace2 = ignoreVerdict "a{2}\n" "aa" == Nothing
prop_regexCloseBracket = ignoreVerdict "a]b\n" "a]b" == Just True
prop_unterminatedClass1 = ignoreVerdict "a[b\n" "a[b" == Just True
prop_unterminatedClass2 = ignoreVerdict "[\n" "[" == Just True
prop_unterminatedClass3 = ignoreVerdict "a[]\n" "a[]" == Just True
prop_unterminatedClass4 = ignoreVerdict "a[!]\n" "a[!]" == Just True
prop_unterminatedClass5 = ignoreVerdict "a[b\n" "ab" == Nothing
prop_anyPatternCompiles = withMaxSuccess 2000 $
    forAll (listOf $ elements "ab0/*?[]!^-\\.:+(){}|$# \r\n") $ \contents ->
        all (\ignorePattern -> isIgnored [ignorePattern] "a/b.sh" `seq` True) $
            parseIgnoreFile contents
segmentRegex :: String -> String
segmentRegex ('\\':c:rest) = escapeLiteral c ++ segmentRegex rest
segmentRegex ('*':rest) = "[^/]*" ++ segmentRegex (dropWhile (== '*') rest)
segmentRegex ('?':rest) = "[^/]" ++ segmentRegex rest
segmentRegex ('[':rest) | Just (classRe, rest') <- classRegex rest = classRe ++ segmentRegex rest'
segmentRegex (c:rest) = escapeLiteral c ++ segmentRegex rest
segmentRegex [] = ""

escapeLiteral :: Char -> String
escapeLiteral c
    | c `elem` ".[]\\()*+?{}|^$" = ['\\', c]
    | otherwise = [c]

prop_class1 = ignoreVerdict "foo[0-9].sh\n" "foo1.sh" == Just True
prop_class2 = ignoreVerdict "foo[0-9].sh\n" "fooa.sh" == Nothing
prop_classList = ignoreVerdict "foo[ab].sh\n" "foob.sh" == Just True
prop_classBang1 = ignoreVerdict "foo[!0-9].sh\n" "foo1.sh" == Nothing
prop_classBang2 = ignoreVerdict "foo[!0-9].sh\n" "fooa.sh" == Just True
prop_classCaret1 = ignoreVerdict "foo[^0-9].sh\n" "foo1.sh" == Nothing
prop_classCaret2 = ignoreVerdict "foo[^0-9].sh\n" "fooa.sh" == Just True
prop_classNegatedNoSlash = ignoreVerdict "a[!x]b\n" "a/b" == Nothing
prop_classRangeNoSlash = ignoreVerdict "a[+-9]b\n" "a/b" == Nothing
prop_classRangeAroundSlash1 = ignoreVerdict "a[+-9]b\n" "a.b" == Just True
prop_classRangeAroundSlash2 = ignoreVerdict "a[+-9]b\n" "a5b" == Just True
prop_classCloseBracketFirst = ignoreVerdict "a[]x]b\n" "a]b" == Just True
prop_classNegatedCloseBracket1 = ignoreVerdict "a[!]]b\n" "a]b" == Nothing
prop_classNegatedCloseBracket2 = ignoreVerdict "a[!]]b\n" "axb" == Just True
prop_classTrailingDash = ignoreVerdict "a[b-]c\n" "a-c" == Just True
prop_classLiteralCaret = ignoreVerdict "a[b^]c\n" "a^c" == Just True
prop_classEscapedCaret1 = ignoreVerdict "a[\\^]c\n" "a^c" == Just True
prop_classEscapedCaret2 = ignoreVerdict "a[\\^]c\n" "abc" == Nothing
prop_classEscapedCaretDash1 = ignoreVerdict "a[\\^-]c\n" "a-c" == Just True
prop_classEscapedCaretDash2 = ignoreVerdict "a[\\^-]c\n" "a^c" == Just True
prop_classEscapedCloseBracket = ignoreVerdict "a[x\\]]c\n" "a]c" == Just True
prop_classOpenBracket = ignoreVerdict "a[[]c\n" "a[c" == Just True
prop_classSpecialRangeEnd1 = ignoreVerdict "a[X-^]c\n" "a]c" == Just True
prop_classSpecialRangeEnd2 = ignoreVerdict "a[X-^]c\n" "aYc" == Just True
prop_classSpecialRangeEnd3 = ignoreVerdict "a[X-^]c\n" "a_c" == Nothing
prop_classRegexSpecials = ignoreVerdict "a[.+$]c\n" "a+c" == Just True
prop_classDotIsLiteral = ignoreVerdict "a[.]c\n" "abc" == Nothing
prop_classPosix1 = ignoreVerdict "a[[:digit:]]c\n" "a1c" == Just True
prop_classPosix2 = ignoreVerdict "a[[:digit:]]c\n" "abc" == Nothing
prop_classPosixNegated = ignoreVerdict "a[![:digit:]]c\n" "abc" == Just True
prop_classReversedRange = ignoreVerdict "a[z-a]c\n" "a[z-a]c" == Just True
-- Takes the pattern following a '[' and returns the regex for the class
-- along with the rest of the pattern. Nothing means the '[' is literal: the
-- class is unterminated, or can't match anything.
classRegex :: String -> Maybe (String, String)
classRegex afterBracket = do
    (items, rest) <- classItems True members
    let pieces = concatMap classRanges [range | Right range <- items]
        chars = nub $ [lo | (lo, hi) <- pieces, lo == hi] ++ ['/' | inverted]
        body = concat [
            filter (`elem` chars) "]",
            concat [[lo, '-', hi] | (lo, hi) <- pieces, lo /= hi],
            concat ["[:" ++ name ++ ":]" | Left name <- items],
            filter (`notElem` "[]^-") chars,
            filter (`elem` chars) "[^-"
            ]
    classRe <- render body
    return (classRe, rest)
  where
    (inverted, members) =
        case afterBracket of
            c:cs | c `elem` "!^" -> (True, cs)
            _ -> (False, afterBracket)

    -- regex-tdfa takes a literal ']' only first, '^' anywhere but first and
    -- '-' only last, and has no escapes inside brackets. Hence the ordering
    -- of the body above, and an alternation when '^' would end up first.
    render body
        | inverted = Just $ "[^" ++ body ++ "]"
        | null body = Nothing
        | '^':others <- body = Just $ "(\\^" ++ concatMap (\c -> ['|', c]) others ++ ")"
        | otherwise = Just $ "[" ++ body ++ "]"

    classItems isFirst s =
        case s of
            ']':rest | not isFirst -> Just ([], rest)
            '[':':':cs | (name, ':':']':rest) <- break (== ':') cs, name `elem` posixClasses ->
                item (Left name) rest
            _ -> do
                (lo, afterLo) <- classChar s
                case afterLo of
                    '-':afterDash | not ("]" `isPrefixOf` afterDash), Just (hi, rest) <- classChar afterDash ->
                        item (Right (lo, hi)) rest
                    _ -> item (Right (lo, lo)) afterLo

    item x rest = do
        (xs, rest') <- classItems False rest
        return (x:xs, rest')

    classChar ('\\':c:rest) = Just (c, rest)
    classChar (c:rest) = Just (c, rest)
    classChar [] = Nothing

    posixClasses = ["alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "xdigit"]

-- Splits a range so that it excludes '/', which a class never matches, and
-- so that the characters regex-tdfa is picky about become single characters
-- rather than range endpoints.
classRanges :: (Char, Char) -> [(Char, Char)]
classRanges (lo, hi) =
    concatMap isolate $ [(lo, min hi '.') | lo < '/'] ++ [(max lo '0', hi) | hi > '/']
  where
    isolate (a, b)
        | a > b = []
        | a == b = [(a, a)]
        | a `elem` "[]^-" = (a, a) : isolate (succ a, b)
        | b `elem` "[]^-" = (b, b) : isolate (a, pred b)
        | otherwise = [(a, b)]

ignoreVerdict :: String -> FilePath -> Maybe Bool
ignoreVerdict contents = isIgnored (parseIgnoreFile contents)

return []
runTests = $quickCheckAll
