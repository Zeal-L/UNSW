import React from 'react';
import { Redirect, Route } from 'react-router-dom';
import AuthContext from '../../AuthContext';

function ProtectedRoute(props) {
  const token = React.useContext(AuthContext);
  console.log(token);
  if (!token) {
    return <Redirect to="/login" />;
  }
  return <Route {...props} />;
}

export default ProtectedRoute;
