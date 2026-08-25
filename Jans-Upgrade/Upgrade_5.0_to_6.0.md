Progress tracking:

1. Adding a modified python upgrade script
2. Main changes to the script so far (comparing to original):
  - Added explicit Flex FQDN specification via commadline argument, to not rely on auto-detection (created an issue in my test environment once)
  - Lines to push into changes to roles / scopes / permissions model (imports data taken from a reference Flex 6.0 db "as is", so it contains inums that may collide with inums existing in target db; may need to improve that part with proper inum generation)
  - Lines to find all users with old "api-admin" role and change the role to new "admin" role - to ensure access to admin UI post-upgrade

To-do list:
1. Currently schema update is conducted as a separate step, importing schema path file into db directly. Is it worth to move that part into the script as well?
2. Need to extend user migration routine and make sure standard roles existing in an older Flex instance will keep admin UI access if they had it prior to upgrade (main blocker seems to be absence of scopes controlling access to license and admin ui session)

Points raised by Alex 

- For "jansAttrUsgTyp" column of "jansAttr" table type is changed from varchar to jsonb. Conversion can't be done automatically by db, instead explicit casting to new type is used atm - need to double-check if it's safe

- The permissions and role mappings model was changed between 5.6 and 6.0 substantionally, apparently. A new table "adminUIResourceScopesMapping" is added which seem to come pre-populated with new mappings of "protected resource (UI/config-api element)" -> "required scopes". Roles and their mappings to scopes in public."jansAppConf" -> "jansConfDyn" -> 'rolePermissionMapping' | 'roles' | 'permissions' JSON elements were changed extensively, with all previous roles seem to be absent (at least in 6.0, need to check in latest also, to make sure it was an intended change), and insteaad a new "admin" role was added. Its scopes also were extended with admin ui session-related scopes, now mandatory to be present to get access to admin UI.

- tem 2 rises a quesion of how to treat older elements of that kind when conducting upgrade. Users may have defined new roles and changed roles - scopes mapping in their systems, to suite their requirements. They may even have changed the default roles and mappings. Thus simply removing the old pre-packaged elements during upgrade may lead to undesired results, even though they seem to not be present at installation anymore. Perhaps discuss it further with the team?

- When populating the new "adminUIResourceScopesMapping" table added in latest version, direct data dump of corresponding entries from a refrence 6.0.0 db was used. Those entries contain inums which uniquness was only enforced in the source db, they are not guaranteed to be unique in the target db (probably?) Perhaps studying of possible consequnces is in order

- "admin" user still hadn't been allowed into admin web UI until I made sure its "jansAdminUIRole" column has only one value ( ["admin"] ) which was the new role with UI session's scopes added to it on the previous steps. If passed as part ofm ultiple values in that array it wasn't properly harvested and as they lacked the said scopes, access still wasn't provided. Needs to be evaluated as it will prevent to preserve roles / permissions layout created by user in their old Gluu Flex instance

- We need to preserve access rights. 
