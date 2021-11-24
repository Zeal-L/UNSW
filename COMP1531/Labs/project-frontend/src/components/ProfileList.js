import React from 'react';
import { List, ListItem, ListItemIcon, ListItemText } from '@material-ui/core';
import AccountCircle from '@material-ui/icons/AccountCircle';
import { Link } from 'react-router-dom';
import { extractUId } from '../utils/token';
import AuthContext from '../AuthContext';

function ProfileList() {
  const uid = extractUId(React.useContext(AuthContext));
  return (
    <List>
      <ListItem button key={'profile'} component={Link} to={`/profile/${uid}`}>
        <ListItemIcon>
          <AccountCircle />
        </ListItemIcon>
        <ListItemText primary="Profile" />
      </ListItem>
    </List>
  );
}

export default ProfileList;
