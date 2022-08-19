package q14.gitlab;

import org.json.JSONObject;

public interface GitlabPermissionsNode {
    public String getName();

    public PermissionsLevel getUserPermissions(User user);
    
    public void updateUserPermissions(User userToUpdate, PermissionsLevel permissions, User userUpdating) throws GitlabAuthorisationException;

    public GitlabGroup createSubgroup(String name, User creator) throws GitlabAuthorisationException;
    
    public GitlabProject createProject(String name, User creator) throws GitlabAuthorisationException;

    public JSONObject toJSON();
}