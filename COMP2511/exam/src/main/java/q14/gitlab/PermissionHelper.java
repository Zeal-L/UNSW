package q14.gitlab;


public final class PermissionHelper {
    public static final void authorise(PermissionsLevel userPermissions, PermissionsLevel requiredPermissionsLevel) throws GitlabAuthorisationException {
        int perms = userPermissions.ordinal();
        int requiredPerms = requiredPermissionsLevel.ordinal();
        if (perms > requiredPerms) {
            throw new GitlabAuthorisationException("User is not authorised");
        }
    }

    public static final void checkPermissionsAlreadyHas(PermissionsLevel userPermissions, PermissionsLevel requiredPermissionsLevel) throws GitlabAuthorisationException {
        int perms = userPermissions.ordinal();
        int requiredPerms = requiredPermissionsLevel.ordinal();
        if (perms <= requiredPerms) {
            throw new GitlabAuthorisationException("User is not authorised");
        }
    }
}
