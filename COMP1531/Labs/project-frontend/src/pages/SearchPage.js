import React from 'react';
import Layout from '../components/Layout';
import ProfileChannelLists from '../components/ProfileChannelLists';
import Search from '../components/Search';

function SearchPage({ match }) {
  const { query_str="" } = match.params;
  return (
    <Layout
      menu={<ProfileChannelLists />}
      body={<Search query_str={query_str} />}
    />
  );
}

export default SearchPage;
