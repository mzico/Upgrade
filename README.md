Progress tracking:

1. Adding a modified python upgrade script
2. Main changes to the script so far (comparing to original):
  - Added explicit Flex FQDN specification via commadline argument, to not rely on auto-detection (created an issue in my test environment once)
  - Lines to push into changes to roles / scopes / permissions model (imports data taken from a reference Flex 6.0 db "as is", so it contains inums that may collide with inums existing in target db; may need to improve that part with proper inum generation)
  - Lines to find all users with old "api-admin" role and change the role to new "admin" role - to ensure access to admin UI post-upgrade

To-do list:
1. Currently schema update is conducted as a separate step, importing schema path file into db directly. Is it worth to move that part into the script as well?
2. Need to extend user migration routine and make sure standard roles existing in an older Flex instance will keep admin UI access if they had it prior to upgrade (main blocker seems to be absence of scopes controlling access to license and admin ui session)
