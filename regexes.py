import re

JSON_REGEX      = '["]?'
EQUALS_REGEX    = '[\ ]?[=\:\,\ ]{1}[\ ]?'
PS_DECLARATION  = '[\(\ ]{1}[\$\"\']{1}'
PS_VARIABLE     = '[\'\"\$]{1}'
FILLER_REGEX    = JSON_REGEX + EQUALS_REGEX + JSON_REGEX
PASSWORD_REGEX  = '[a-zA-Z0-9\@\-\.\!\?\\\/\$\=\^\%\(\)\*\&\#\~\`\'\"\[\]\_\+\<\>]+'
DOMAIN_USER     = '[a-zA-Z0-9\.\@\_\\\%]+' # Need to add percentile to match batch variables.

"""
queries should be a list of dictionaries. Dictionaries should be of the form:
{
    "search_term" : "Term or string to search on github.",
    "regex"       : "The regex to indicate whether a search result was valid.",
    "language"    : "If you want to restrict the language you're searching, indicate it here",
    "inpath"      : boolean, to determine if we should add "in:path" to the search query,
    "infile"      : boolean, to determine if we should add "in:file" to the search query,
    "path"        : "Path that the file must reside in.",
    "filename"    : "Filename that you want to search.",
    "extension"   : "Only match files with this extension"
    "flags"       : "compile regex with these flags"
}
"""
queries = [
    # Search for regular aws_secret_key. This is defined by the awscli and used by the python package.
    {
        "search_term": "aws_secret_key",
        "regex"      : "[0-9a-zA-Z\\\/\+\=]{40}",
        "language"   : "",
        "inpath"     : False,
        "infile"     : False,
        "path"       : "",
        "filename"   : "",
        "extension"  : "",
        "flags"      : "",
    },
    # Search for all ldap.conf files with 
    {
        "search_term" : "bindpw",
        "regex"       : "(bindpw" + FILLER_REGEX + PASSWORD_REGEX + ")",
        "language"    : "",
        "inpath"      : False,
        "infile"      : False,
        "path"        : "",
        "filename"    : "ldap.conf",
        "extension"   : "",
        "flags"       : "",
    },

    # Another password configuration detail.
    {
        "search_term" : "ldap.password",
        "regex"       : "(ldap.password" + FILLER_REGEX + PASSWORD_REGEX + ")",
        "language"    : "",
        "inpath"      : False,
        "infile"      : False,
        "path"        : "",
        "filename"    : "",
        "extension"   : "",
        "flags"       : "",
    },
    # Another password configuration detail.
    {
        "search_term" : "LDAP_PASSWORD",
        "regex"       : "(LDAP_PASSWORD" + FILLER_REGEX + PASSWORD_REGEX + ")",
        "language"    : "",
        "inpath"      : False,
        "infile"      : False,
        "path"        : "",
        "filename"    : "",
        "extension"   : "",
        "flags"       : "",
    },
    # Search for definitions of new PS Credentials. Useful for digging up configuration scripts.
    {
        "search_term" : "System.Management.Automation.PSCredential",
        "regex"       : "(New-Object.*System.Management.Automation.PSCredential.*$)",
        "language"    : "powershell",
        "inpath"      : False,
        "infile"      : False,
        "path"        : "",
        "filename"    : "",
        "extension"   : "",
        "flags"       : re.IGNORECASE,
    },
    # Attempt to match the net user commands.
    {
        "search_term" : "net user",
        "regex"       : "(net(\.exe)? user(\ \/[adAD]{3})? " + DOMAIN_USER + " " + PASSWORD_REGEX + ")",
        "language"    : "powershell",
        "inpath"      : False,
        "infile"      : False,
        "path"        : "",
        "filename"    : "",
        "extension"   : "",
        "flags"       : re.IGNORECASE,
    },
    # Catch the batch case as well.
    {
        "search_term" : "net user",
        "regex"       : "(net(\.exe)? user(\ \/[adAD]{3})? " + DOMAIN_USER + " " + PASSWORD_REGEX + ")",
        "language"    : "batch",
        "inpath"      : False,
        "infile"      : False,
        "path"        : "",
        "filename"    : "",
        "extension"   : "",
        "flags"       : re.IGNORECASE,
    },
    # Search for secret strings being converted in plaintext
    {
        "search_term" : "ConvertTo-SecureString",
        "regex"       : "(ConvertTo-SecureString.*AsPlainText.*)",
        "language"    : "powershell",
        "inpath"      : False,
        "infile"      : False,
        "path"        : "",
        "filename"    : "",
        "extension"   : "",
        "flags"       : re.IGNORECASE

    }
]
