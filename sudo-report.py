#!/usr/bin/python
'''
 2016 - March - 2
 Author: Jerel Gilmer
'''

import os
import sys
import ldap

def print_usage():
 print "Usage: server-access-report.py <hostname>"
 print "This script generates the list of sudo rules for each server.\n"
 print "<hostname> - System hostname; This can be the short name\n"
 print "For report of all systems, use \'.\'\n"
 print "Make sure to set the below variables in the script:"
 print "\tDOMAIN: Domain component"
 print "\tLDAP_SERVER: LDAP server to be queried"
 print "\tLDAP_USER: LDAP user to query server; preferable a read-only account" 
 print "\tLDAP_PW: LDAP user's password\n"
 sys.exit(1)

try:
 server = str(sys.argv[1])
except:
 print_usage()

## LDAP Connection Info and bind to the LDAP server
## Uncomment and set these variables to the appropriate values
## Below are examples 
#DOMAIN = "dc=sub,dc=example,dc=com"
#LDAP_SERVER = "ldap://ipaserver1"
#LDAP_USER = "uid=user1,cn=users,cn=compat," + DOMAIN
#LDAP_PW = "Password123"

try:
 DOMAIN 
 LDAP_SERVER
 LDAP_USER 
 LDAP_PW
except:
 print_usage()

l = ldap.initialize(LDAP_SERVER)

l.simple_bind_s(LDAP_USER,LDAP_PW)

## LDAP Search Variables
## Base DN for LDAP Searches
baseComputerDN = "cn=computers,cn=accounts," + DOMAIN
baseGroupDN =  "cn=groups,cn=accounts," + DOMAIN
baseUserDN = "cn=users,cn=accounts," + DOMAIN
baseSudoDN = "cn=sudorules,cn=sudo," + DOMAIN
baseSudoCmdDN = "cn=sudocmds,cn=sudo," + DOMAIN
baseSudoCmdGroupDN = "cn=sudocmdgroups,cn=sudo," + DOMAIN

## Default LDAP SCOPE
scope = ldap.SCOPE_SUBTREE

## Filter for LDAP Searches
compFilter = "(&(objectclass=ipahost)(fqdn=*" + server + "*))"
userFilter = "(objectclass=person)"
groupFilter = "(objectclass=ipausergroup)"
sudoFilter = "objectclass=ipasudorule"
sudoCmdFilter = "objectclass=ipasudocmd"
sudoCmdGroupFilter = "objectclass=ipasudocmdgrp"

## Attributes from LDAP Searches
compAttributes =  ['memberOf', 'fqdn']
userAttributes = ['uid']
groupAttributes = ['member']
sudoAttributes = ['memberUser', 'ipaSudoOpt', 'memberAllowCmd', 'hostCategory', 'cmdCategory']
sudoCmdAttributes = ['sudoCmd']
sudoCmdGroupAttributes = ['member']

## Perform LDAP searches and store results into array
ALL_HOSTS = l.search_s(baseComputerDN, scope, compFilter, compAttributes)

ALL_USERS = l.search_s(baseUserDN, scope, userFilter, userAttributes)

ALL_GROUPS = l.search_s(baseGroupDN, scope, groupFilter, groupAttributes)

ALL_SUDORULES = l.search_s(baseSudoDN, scope, sudoFilter, sudoAttributes)

ALL_SUDOCMDS = l.search_s(baseSudoCmdDN, scope, sudoCmdFilter, sudoCmdAttributes)

ALL_SUDOCMDGROUPS = l.search_s(baseSudoCmdGroupDN, scope, sudoCmdGroupFilter, sudoCmdGroupAttributes)

# HBAC rules that apply to all servers
sudoAllServersFilter = "(&(objectclass=ipasudorule)(hostCategory=all))"
SUDORULE_ALL_SERVERS = l.search_s(baseSudoDN, scope, sudoAllServersFilter, sudoAttributes)

ALL_HOSTS.sort()

def findUID(user):
 uid = filter(lambda x: user in x, ALL_USERS)
 return uid[0][1]['uid'][0]

def findGroupMembers(groupname):
 if "cn=groups,cn" not in groupname:
  pass
 group = filter(lambda x: groupname in x, ALL_GROUPS)
 try:
  groupmembers = group[0][1]['member']
 except: 
  groupmembers = ""
 for user in groupmembers:
  if "cn=groups,cn" in user:
   for i in findGroupMembers(user):
    yield i
  else:
   yield (findUID(user))
  
def findSudoCmds(sudo_cmd):
 #print "SUDO_CMD =", sudo_cmd
 s = filter(lambda x: sudo_cmd in x, ALL_SUDOCMDS)
 return s[0][1]['sudoCmd'][0]

def findSudoCmdGroupMembers(sudo_cmd_group):
 allSudoCmds = []
 sudoGroup = filter(lambda x: sudo_cmd_group in x, ALL_SUDOCMDGROUPS)
 sudoGroupMembers = sudoGroup[0][1]['member']
 for i in sudoGroupMembers:
  allSudoCmds.append(findSudoCmds(i))
 formattedAllSudoCmds = ', '.join(allSudoCmds)
 return formattedAllSudoCmds

def sudoOnAllSystems():
 allSystemsSudoRules = {} 

 for sudoname in SUDORULE_ALL_SERVERS:
  sudorule = filter(lambda x: sudoname[0] in x, ALL_SUDORULES)
  
  for sudouser in sudorule:
   sudocmds = []
   allowedUsers = []
   allowedSudoCmd = []
   users = []
   groups = []

   try:
    sudoOptions = ['ipaSudoOpt']
   except:
    sudoOptions = []
   
   try:
    sudocmds = sudouser[1]['memberAllowCmd']
    for i in sudocmds:
     if "cn=sudocmdgroups,cn" in i:
      allowedSudoCmd.append(findSudoCmdGroupMembers(i))
     else:
      allowedSudoCmd.append(findSudoCmds(i))
   except:
    try:
     if sudouser[1]['cmdCategory']:
      allowedSudoCmd = sudouser[1]['cmdCategory'][0]
    except:
     allowedSudoCmd = ['None']

   try:
    sudocmdgroup = filter(lambda x: "cn=sudocmdgroups" in x, sudouser[1]['memberAllowCmd'])
   except:
    sudocmdgroup = ''

   try:
    users = filter(lambda x: "cn=users,cn" in x, sudouser[1]['memberUser'])
   except:
    users = []

   try:
    groups = filter(lambda x: "cn=groups,cn" in x, sudouser[1]['memberUser'])
   except:
    groups = []

   for i in users:
    allowedUsers.append(findUID(i))

   for i in groups:
    allowedUsers += (findGroupMembers(i))
 
  allSystemsSudoRules[sudorule[0][0]] = {'sudoCommands': allowedSudoCmd, 'allowedUsers': allowedUsers}

 return allSystemsSudoRules

def mergeD(results,allowedSudoCmd):
 for k in results:
  if allowedSudoCmd == results[k]['sudoCommands']:
   return "MATCH!!", k

def nestedL(l):
 if isinstance(l, str):
  yield l
 for k in l:
  if isinstance(k, list):
   for i in k:
    yield i
  if isinstance(k, str):
   yield k

def main():
 for entry in ALL_HOSTS:
  SudoAllowedList = {}
  results = {}
  x = 1  

  fqdn = entry[1]['fqdn'][0]
 
  print "HOSTNAME = ", fqdn

  try:
   membership = filter(lambda x: "sudo,dc" in x, entry[1]['memberOf'])
  except:
   membership = []

  for sudoname in membership:
   #print "SUDONAME =" , sudoname
   sudorule = filter(lambda x: sudoname in x, ALL_SUDORULES)
   #print "SUDORULE =" , sudorule
   for sudouser in sudorule:
    allowedUsers = []
    allowedUsersLst = []
    allowedSudoLst = []
    allowedSudoCmd = []
    users = []
    groups = []
    #print "SUDOUSER =", sudouser

    try:
     sudoOptions = ['ipaSudoOpt']
    except:
     sudoOptions = []

    try:
     sudocmds = sudouser[1]['memberAllowCmd']
     for i in sudocmds:
      if "cn=sudocmdgroups,cn" in i:
       allowedSudoCmd.append(findSudoCmdGroupMembers(i))
      else:
       allowedSudoCmd.append(findSudoCmds(i))
    except:
     try:
      if sudouser[1]['cmdCategory']:
       allowedSudoCmd = sudouser[1]['cmdCategory'][0]
     except:
      allowedSudoCmd = ['None']

    #print "SUDOCMDS =", sudocmds
    #print "SUDOCMDGROUP =", sudocmdgroup
    try:
     users = filter(lambda x: "cn=users,cn" in x, sudouser[1]['memberUser'])
    except: 
     users = []
 
    try:
     groups = filter(lambda x: "cn=groups,cn" in x, sudouser[1]['memberUser'])
    except:
     groups = []

    for i in users:
     allowedUsers.append(findUID(i))

    for i in groups:
     allowedUsers += findGroupMembers(i)
   
   #print "Allowed Sudo Commands", allowedSudoCmd
   #print "Allowed Users", allowedUsers, "\n"

  
    SudoAllowedList[sudorule[0][0]] = {'sudoCommands': allowedSudoCmd, 'allowedUsers': allowedUsers}

  systemWide = sudoOnAllSystems()
  SudoAllowedList.update(systemWide)

  for key, value in SudoAllowedList.iteritems():
  
   if isinstance(value['sudoCommands'], list):
    allowedSudoCmd = ', '.join(value['sudoCommands'])
   else:
    allowedSudoCmd = value['sudoCommands']

   allowedUsers = value['allowedUsers']

  # print allowedSudoCmd

   try:
    mark, key = mergeD(results,allowedSudoCmd)
   except:
    mark, key = (None, None)

   if mark == "MATCH!!":
    results[key]['allowedUsers'].append(allowedUsers)
   else:
    results[x] = {'sudoCommands': allowedSudoCmd, 'allowedUsers': allowedUsers}
    x = x + 1

  for i in results:
   results_allowedSudoCmd = results[i]['sudoCommands']
 
   results_allowedUsers = list(nestedL(results[i]['allowedUsers']))
   results_allowedUsersSet = set(results_allowedUsers)
   results_allowedUsersLst = list(results_allowedUsersSet)
   results_allowedUsersLst.sort()
   formatted_allowedUsers = ' '.join(results_allowedUsersLst)

   if not results_allowedSudoCmd:
    results_services = 'empty'
   if not formatted_allowedUsers:
    formatted_allowedUsers = 'empty'
   print "SUDO COMMANDS = ", results_allowedSudoCmd
   print "ALLOWED USERS = ", formatted_allowedUsers, "\n"

main()
