import React from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

import {
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListSubheader,
} from '@material-ui/core';

import RadioButtonCheckedIcon from '@material-ui/icons/RadioButtonChecked';
import RadioButtonUncheckedIcon from '@material-ui/icons/RadioButtonUnchecked';
import AuthContext from '../AuthContext';
import AddDmDialog from './Dm/AddDmDialog';

import { useStep } from '../utils/update';

function DmList({ dm_id: curr_dm_id }) {
  const [myDms, setMyDms] = React.useState([]);

  const token = React.useContext(AuthContext);

  const fetchDmsData = () => {
    axios
      .get('/dm/list/v1', {
        params: {
          token,
        },
      })
      .then(({ data }) => {
        setMyDms(data['dms']);
      })
      .catch((err) => { });
  };

  useStep(fetchDmsData, [], 2);

  return (
    <>
      <List
        subheader={
          <ListSubheader style={{ display: 'flex' }}>
            <span style={{ flex: 1 }}>My Dms</span>
            <AddDmDialog callback={fetchDmsData} />
          </ListSubheader>
        }
      >
        {myDms.map(({ dm_id, name }) => (
          <ListItem
            button
            key={dm_id}
            component={Link}
            to={`/dm/${dm_id}`}
          >
            <ListItemIcon>
              {dm_id == curr_dm_id ? (
                <RadioButtonCheckedIcon />
              ) : (
                <RadioButtonUncheckedIcon />
              )}
            </ListItemIcon>
            <ListItemText primary={name} />
          </ListItem>
        ))}
      </List>
    </>
  );
}

export default DmList;
