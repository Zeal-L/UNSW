import React from 'react';
import ProfileList from './ProfileList';
import ChannelList from './ChannelList';
import DmList from './DmList';

function ProfileChannelLists({ channel_id, dm_id }) {
  return (
    <>
      <ProfileList />
      <ChannelList channel_id={channel_id} />
      <DmList dm_id={dm_id} />
    </>
  );
}

export default ProfileChannelLists;
