import React from 'react';
import Layout from '../components/Layout';
import ProfileChannelLists from '../components/ProfileChannelLists';
import Profile from '../components/Profile';

function ProfilePage({ match }) {
  const { profile } = match.params;
  return (
    <Layout
      menu={<ProfileChannelLists />}
      body={<Profile profile={profile} />}
    />
  );
}

export default ProfilePage;