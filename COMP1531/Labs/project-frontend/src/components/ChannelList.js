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
import AddChannelDialog from './Channel/AddChannelDialog';

import { useStep } from '../utils/update';

function ChannelList({ channel_id: curr_channel_id }) {
  const [myChannels, setMyChannels] = React.useState([]);
  const [allChannels, setAllChannels] = React.useState([]);

  const token = React.useContext(AuthContext);

  const fetchChannelsData = () => {
    // fetch channels data
    const getMyChannels = axios.get('/channels/list/v2', { params: { token } });
    const getAllChannels = axios.get('/channels/listall/v2', { params: { token } });

    axios.all([getMyChannels, getAllChannels]).then(
      axios.spread((myChannelResponse, allChannelResponse) => {
        const myChannelData = myChannelResponse.data.channels;
        const allChannelData = allChannelResponse.data.channels;
        const filteredChannels = allChannelData.filter((channel) => {
          return (
            myChannelData.find((c) => c.channel_id === channel.channel_id) ===
            undefined
          );
        });
        setMyChannels(myChannelData);
        setAllChannels(filteredChannels);
      })
    );
  };

  useStep(fetchChannelsData, [], 2);

  return (
    <>
      <List
        subheader={
          <ListSubheader style={{ display: 'flex' }}>
            <span style={{ flex: 1 }}>My Channels</span>
            <AddChannelDialog callback={fetchChannelsData} />
          </ListSubheader>
        }
      >
        {myChannels.map(({ channel_id, name }, index) => (
          <ListItem
            button
            key={channel_id}
            component={Link}
            to={`/channel/${channel_id}`}
          >
            <ListItemIcon>
              {channel_id == curr_channel_id ? (
                <RadioButtonCheckedIcon />
              ) : (
                <RadioButtonUncheckedIcon />
              )}
            </ListItemIcon>
            <ListItemText primary={name} />
          </ListItem>
        ))}
      </List>
      <List subheader={<ListSubheader>Other Channels</ListSubheader>}>
        {allChannels.map(({ channel_id, name }, index) => (
          <ListItem
            button
            key={channel_id}
            component={Link}
            to={`/channel/${channel_id}`}
          >
            <ListItemIcon>
              {channel_id == curr_channel_id ? (
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

export default ChannelList;
