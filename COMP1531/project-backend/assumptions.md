# Assumptions
## W13A - Beagle
### Assumption 1
- In channel_invite, we assume that auth_user_id is the user sending the invitation to the channel, and u_id is the user receiving the invitation to the channel.
### Assumption 2
- INT_MIN (-2147483648) will never be used as an ID value as we use it for our default value in the data store. As well as this, we assume that channel_id and u_id will always be positive.
### Assumption 3
- We assume the original state of the program contains a data store with a single dictionary for 'users', 'channels' and 'messages'. This prevents the potential for key errors when the program has begun and has functions accessing the data store without having fields initalized.
### Assumption 4
- We are assuming that all inputs are valid other then email and have not implemented any input sanitization. This has the potential to cause an unforeseen exception in our code.
### Assumption 5
- We assumed that the user(s) who created the channel will be added to both owner_members and all_members. This makes it easier to check if a user is an authorised member by only needing to check all_members then both owner_members and all_members.
### Assumption 6
- We assume that users are likely to try to log in without registering, so checks have been added for this purpose. Moreover, we assumed that channel functions won't be called without creating a channel and a user as well.
