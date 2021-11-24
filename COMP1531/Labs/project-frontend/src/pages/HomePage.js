import React from 'react';
import Layout from '../components/Layout';
import ProfileChannelLists from '../components/ProfileChannelLists';
import WorkspaceStats from '../components/WorkspaceStats';
import { Typography } from '@material-ui/core';

function HomePage() {
  return (
    <Layout
      menu={<ProfileChannelLists />}
      body={
        <>
          <Typography variant="h4">WELCOME</Typography>
          <div style={{ paddingTop: 15 }}>
            <Typography variant="body1">
              This is Streams: agile messaging for Software Engineers
            </Typography>
          </div>
          <br />
          <WorkspaceStats />
        </>
      }
    />
  );
}

export default HomePage;
