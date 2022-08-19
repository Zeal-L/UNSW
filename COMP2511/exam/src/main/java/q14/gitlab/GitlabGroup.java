package q14.gitlab;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;

public class GitlabGroup implements GitlabPermissionsNode {

    private String name;
    private Map<User, PermissionsLevel> members = new HashMap<User, PermissionsLevel>();
    private List<GitlabPermissionsNode> subgroups = new ArrayList<GitlabPermissionsNode>();

    public GitlabGroup(String name, User creator) {
        this.name = name;
        members.put(creator, PermissionsLevel.OWNER);
    }

    public String getName() {
        return name;
    }

    @Override
    public PermissionsLevel getUserPermissions(User user) {
        return members.get(user);
    }

    public List<String> getUsersOfPermissionLevel(PermissionsLevel level) {
        Set<User> membersSet = members.keySet();
        List<String> names = new ArrayList<String>();
        membersSet.stream()
                .filter(member -> members.get(member).equals(level))
                .forEach(member -> names.add(member.getName()));
        return names;
    }

    @Override
    public void updateUserPermissions(User userToUpdate, PermissionsLevel permissions, User updatingUser)
            throws GitlabAuthorisationException {
        
        PermissionHelper.authorise(getUserPermissions(updatingUser), PermissionsLevel.OWNER);

        addMemberRecursive(userToUpdate, permissions, updatingUser);
    }

    private void addMemberRecursive(User userToUpdate, PermissionsLevel permissions, User updatingUser) throws GitlabAuthorisationException {
        if (members.containsKey(userToUpdate)) {
            PermissionHelper.checkPermissionsAlreadyHas(members.get(userToUpdate), permissions);
        }
        members.put(userToUpdate, permissions);
        for (GitlabPermissionsNode subgroup : subgroups) {
            subgroup.updateUserPermissions(userToUpdate, permissions, updatingUser);
        }
    }

    @Override
    public GitlabGroup createSubgroup(String name, User user) throws GitlabAuthorisationException {
        PermissionHelper.authorise(getUserPermissions(user), PermissionsLevel.MAINTAINER);

        GitlabGroup group = new GitlabGroup(name, user);
        subgroups.add(group);
        return group;
    }

    @Override
    public GitlabProject createProject(String name, User user) throws GitlabAuthorisationException {
        PermissionHelper.authorise(getUserPermissions(user), PermissionsLevel.DEVELOPER);

        GitlabProject project = new GitlabProject(name, user);
        subgroups.add(project);
        return project;
    }

    @Override
    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        json.put("type", "group");
        json.put("name", name);

        JSONArray subgroupJSON = new JSONArray(
                subgroups.stream()
                        .map(GitlabPermissionsNode::toJSON)
                        .collect(Collectors.toList()));

        json.put("subgroups", subgroupJSON);

        return json;
    }
}