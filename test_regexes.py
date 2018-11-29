#!/usr/bin/env python

import re
from regexes import queries
from termcolor import colored

# Tests is a dictionary where each key should corrolate to a search_term
# from regexes.queries, and its value is a list of strings that should _positively_
# match against.

tests = {
    "aws_secret_key": [
            "aws_secret_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "aws_secret_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "aws_secret_key=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "aws_secret_key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "aws_secret_key\": \"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\"",
            "aws_secret_key\":\"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\"",

        ], 
    "bindpw": [
            "bindpw Pa55w0rd",
            "bindpw P@$$w*rD!",
            "bindpw = \"P@$$w0rd\"",
            "bindpw = P@$$w0rd!()",
            "bindpw=\"9A$$w0rd\"",
            "bindpw=P@55w0rd!",
            "bindpw\": \"Pa$$w<0>rd\"",
            "bindpw\":\"Pa$$w<0>rd\""
        ],
    "ldap.password": [
            "ldap.password Pa55w0rd",
            "ldap.password P@$$w*rD!",
            "ldap.password = \"P@$$w0rd\"",
            "ldap.password = P@$$w0rd!()",
            "ldap.password=\"9A$$w0rd\"",
            "ldap.password=P@55w0rd!",
            "ldap.password\": \"Pa$$w<0>rd\"",
            "ldap.password\":\"Pa$$w<0>rd\""
        ], 
    "LDAP_PASSWORD": [
            "LDAP_PASSWORD Pa55w0rd",
            "LDAP_PASSWORD P@$$w*rD!",
            "LDAP_PASSWORD = \"P@$$w0rd\"",
            "LDAP_PASSWORD = P@$$w0rd!()",
            "LDAP_PASSWORD=\"9A$$w0rd\"",
            "LDAP_PASSWORD=P@55w0rd!",
            "LDAP_PASSWORD\": \"Pa$$w<0>rd\"",
            "LDAP_PASSWORD\":\"Pa$$w<0>rd\""
        ], 
    "System.Management.Automation.PSCredential": [
            "filler\nNew-Object System.Management.Automation.PSCredential($Username, $Password)",
            "New-Object System.Management.Automation.PSCredential $Username, $Password",
            "New-Object System.Management.Automation.PSCredential($USERNAME,$Password)",
            "New-Object System.Management.Automation.PSCredential $USERNAME,$Password",
            "New-Object System.Management.Automation.PSCredential(\"DOMAIN\Administrator\", \"Pa$$w0rd!\")",
            "New-Object System.Management.Automation.PSCredential(\"DOMAIN\Administrator\",\"Pa$$w0rd!\")",
            "New-Object System.Management.Automation.PSCredential \"DOMAIN\Administrator\", \"Pa$$w0rd!\"",
            "New-Object System.Management.Automation.PSCredential \"DOMAIN\Administrator\",\"Pa$$w0rd!\"",
            "new-object system.management.automation.pscredential \"omega\" \"lul\"",
            "new-object system.management.automation.pscredential($omega,$lol)",
        ],
    "net user": [
            "net.exe user /ADD Administrator Pa55w0rd",
            "net user /add DOMAIN\\admin P@$$w0rd",
            "net.exe user DOMAIN\\user Sup3rS33cR!7 /add",
            "net.exe user %foo% %bar%",
            "net.exe user /ADD %admin% pA55w0rd",
            "NET.EXE USER /ADD ADMINISTRATOR PASSWORD"
        ],
    "ConvertTo-SecureString": [
            "convertto-securestring -asplaintext -string \"lol\"",
            "ConVertTo-SecUreStrIng \"P@44as29rw09rd\" -AsPlainText -Force;",
            "ConvertTo-SecureString $secpass -AsPlainText",
            "ConvertTo-SecureString -Force -AsPlainText -String $password",
            "shouldn't match this lol"
        ]
}

def build_regex(query):
    if query["flags"]:
        term = re.compile(query["regex"], query["flags"])
    else:
        term = re.compile(query["regex"])
    return term

for query in queries:
    if query["search_term"] in tests.keys():
        for test_string in tests[query["search_term"]]:
            reg = build_regex(query)
            result = reg.search(test_string)
            if result:
                print(colored("[SUCCESS] {} matched to: {}".format(test_string, result[0]), "green"))
            else:
                print(colored("[FAILURE] {} FAILED to match regex: {}".format(test_string, query["regex"]), "red"))

