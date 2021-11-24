import React from 'react';
import { makeStyles } from '@material-ui/core/styles';
import { drawerWidth } from '../../utils/constants';

const useStyles = makeStyles((theme) => ({
  body: {
    [theme.breakpoints.up('sm')]: {
      width: `calc(100% - ${drawerWidth}px)`,
    },
    padding: 20,
  },
  toolbar: theme.mixins.toolbar,
}));

function Body({ children }) {
  const classes = useStyles();
  return (
    <div className={classes.body}>
      {/* Padding */}
      <div className={classes.toolbar} />
      {children}
    </div>
  );
}

export default Body;
