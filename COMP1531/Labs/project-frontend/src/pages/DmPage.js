import React from 'react';
import Layout from '../components/Layout';
import ProfileChannelLists from '../components/ProfileChannelLists';
import Dm from '../components/Dm';

function DmPage({ match }) {
  const { dm_id } = match.params;
  return (
    <Layout
      menu={<ProfileChannelLists channel_id={null} dm_id={dm_id} />}
      body={<Dm dm_id={dm_id} />}
    />
  );
}

export default DmPage;
