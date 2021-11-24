import React from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import Button from '@material-ui/core/Button';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import AuthContext from '../AuthContext';

export default function NotificationList() {

  const [open, setOpen] = React.useState(false);
  const [notifs, setNotifs] = React.useState([]);
  const buttonRef = React.useRef();
  const token = React.useContext(AuthContext);

  React.useEffect(() => {
    const interval = setInterval(async () => {
      axios
        .get('/notifications/get/v1', {
          params: { token },
        })
        .then(({ data }) => {
          setNotifs(data.notifications);
        })
        .catch((err) => { });
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const handleClick = (event) => setOpen(true);
  const handleClose = () => setOpen(false);

  return (
    <div>
      <Button
        ref={buttonRef}
        aria-controls="simple-menu"
        aria-haspopup="true"
        onClick={handleClick}
        color="inherit"
      >
        Notifications
      </Button>
      <Menu
        id="simple-menu"
        anchorEl={buttonRef.current}
        keepMounted
        open={open}
        onClose={handleClose}
      >
        {notifs.length === 0
          ? <div>&nbsp;You don't have any notifications.&nbsp;</div>
          : notifs.map((notif) => {
            if (notif.dm_id === -1) {
              return (
                <MenuItem component={Link} to={`/channel/${notif.channel_id}`}>
                  {notif.notification_message}
                </MenuItem>
              )
            } else {
              return (
                <MenuItem component={Link} to={`/dm/${notif.dm_id}`}>
                  {notif.notification_message}
                </MenuItem>
              )
            }
          })}
        <MenuItem onClick={handleClose}>Close</MenuItem>
      </Menu>
    </div>
  );
}