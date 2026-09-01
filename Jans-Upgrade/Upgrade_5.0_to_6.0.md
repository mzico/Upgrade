### Progress tracking:

1. Adding a modified python upgrade script
2. Main changes to the script so far (comparing to original):
   - Added explicit Flex FQDN specification via commadline argument, to not rely on auto-detection (created an issue in my test environment once)
   - Lines to push into changes to roles / scopes / permissions model (imports data taken from a reference Flex 6.0 db "as is", so it contains inums that may collide with inums existing in target db; may need to improve that part with proper inum generation)
   - Lines to find all users with old "api-admin" role and change the role to new "admin" role - to ensure access to admin UI post-upgrade
   - Fixed Casa integration (new required scope is added to Casa's client)
   - Fixed permissions on Admin UI's policy folders preventing from uploading new policy stores
3. Got some detailed explanations of how new access control system works from the dev channel. Playing with it in Agama lab, trying to see if old roles can be recreated and included in a policy store file
4. Tested OIDC flows post-upgrade succesfully
5. All three configured Casa plugins (account linking, email otp, OTP token) seem to survive migration now, and function properly after
6. Custom branding for Casa (logo+icon) migrates too

### To-do list:
1. Currently schema update is conducted as a separate step, importing schema path file into db directly. Perhaps move it into the script as well later?
2. ~Need to extend user migration routine and make sure standard roles existing in an older Flex instance will keep admin UI access if they had it prior to upgrade~ This seems like more and more disproportionally complex and unreasonable task, as it's hard to correctly distinguish which old custom roles (if created by user) should have access to what in updated access control model. "admin" role is already ensured access to admin UI, and then will allow users to define a new system of roles, compatible with the new model. One relatively easy solution though is to recreated our standard old roles in the new system as close as possible, then push then into the default policy store we already modify in the script (on to-do list)

### Points of concern

  - For "jansAttrUsgTyp" column of "jansAttr" table type is changed from varchar to jsonb. Conversion can't be done automatically by db, instead explicit casting to new type is used atm - need to double-check if it's safe
  - ~When populating the new "adminUIResourceScopesMapping" table added in latest version, direct data dump of corresponding entries from a refrence 6.0.0 db was used. Those entries contain inums which uniquness was only enforced in the source db, they are not guaranteed to be unique in the target db (probably?) Perhaps studying of possible consequences is in order~ Have checked Flex's setup scripts' sources, it uses the same way of importing them there too (so imports fully-rendered LDIF files (not templates as usual), with static inums in them); looks weird, but probably trust the developer on that one?
  - It seems like "jansAdminUIRole" of user entries is declared as multi-value attribute - but previously when I had "admin" role on a user as part of json array (so not a single "admin" value), it wasn't recognized as admin. what is an expected behavior here, can users have multiple roles?
  - Do we need to include SAML in those tests? Original installation didn't have SAML capabilities, as it was never mentioned

