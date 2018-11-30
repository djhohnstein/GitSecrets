# GitSecrets

## Description

GitSecrets is a *Python 3* project to automate the searching of secrets in both Github and Github Enterprise environments. Often times organizaitons will manage source code through an internal Github Enterprise repository; however, in larger organizations searching through thousands of repos is unfeasible. This script aims to eliminate the overhead in searching through repositories manually.

## Modes

Currently the main script contains only two modes:
- Searching through Github and matching results based on regex
- Cloning all repositories from a user or organization and running trufflehog on all repositories.

### Searching

Searching behavior is defined in the file `regexes.py`. The syntax of how you should structure custom search terms is defined within the file, but in general these terms are dictionaries compromised of several keys, the two main ones being `search_term` and `regex`.

`search_term` is the term that you'll be searching Github for. 
`regex` is the regex that will indicate a positive match has been found relating to your keyword.

By default, the script will search for all terms within the `regex.py` file, though you can specify which is best. (Note: Searching https://github.com will get you throttled for abuse; don't do it!)

### User Secret Hunting

The second mode of this script will clone every repository belonging to a user or organization then run `trufflehog` on them (a tool for digging for high entropy strings in git repositories and commits. [Source Code](https://github.com/dxa4481/truffleHog)). It will log the results in a folder under the current directory, in the format of `trufflehog/$USER/` for manual review later.

## Usage

```bash
Usage: gitsecrets.py [options]

Options:
  -h, --help            show this help message and exit
  -g GITHUB_URL, --github_url=GITHUB_URL
                        URL of the Github server in quesiton.
  -c COOKIES, --cookies=COOKIES
                        Cookies file in JSON format.
  -u GITHUB_USER, --user=GITHUB_USER
                        User of repositories you wish to clone and run
                        trufflehog on.
  -s SEARCH, --search=SEARCH
                        Comma separated list of search terms from regexes.py
                        to search for. By default, searches all. Otherwise,
                        can be one or more of: aws_secret_key, bindpw,
                        ldap.password, LDAP_PASSWORD,
                        System.Management.Automation.PSCredential, net user,
                        ConvertTo-SecureString
  -o OUTFILE, --outfile=OUTFILE
                        Outfile to write search results to. This is not used
                        when -u is passed. Default is "search_results.txt"
```

## Examples

### Searching Examples

Search for ldap.conf files containing the "bindpw" string (defined in regexes.py) using the cookies.json file..

- `python .\gitsecrets.py -g https://github.com -s "bindpw" -c .\cookies.json`

Search all of Github for each query in regexes.py and write to all_results.txt

- `python .\gitsecrets.py -g https://github.com -c .\cookies.json`

### Cloning Examples

Clone every repository from user djhohnstein and run trufflehog on each repo. Results will be in `trufflehog/djhohnstein/*.trufflehog`.

- `python .\gitsecrets.py -g https://github.com -u djhohnstein -c .\cookies.json` 
