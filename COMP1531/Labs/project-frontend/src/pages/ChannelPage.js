import React from 'react';
import Layout from '../components/Layout';
import ProfileChannelLists from '../components/ProfileChannelLists';
import Channel from '../components/Channel';

function ChannelPage({ match }) {
  const { channel_id } = match.params;
  return (
    <Layout
      menu={<ProfileChannelLists channel_id={channel_id} dm_id={null} />}
      body={<Channel channel_id={channel_id} />}
    />
  );
}

export default ChannelPage;
