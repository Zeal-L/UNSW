import React from 'react';
import axios from 'axios';

import {
  Dialog,
  DialogTitle,
  DialogActions,
  DialogContent,
  MenuItem,
  Select,
  DialogContentText,
  Button,
  IconButton,
  TextField,
} from '@material-ui/core';
import ArrowForwardIcon from '@material-ui/icons/ArrowForward';

import AuthContext from '../../AuthContext';
import { useStep } from '../../utils/update';

function MessageShareDialog({ og_message_id, ...props }) {
  const [open, setOpen] = React.useState(false);
  const [selectedChannel, setSelectedChannel] = React.useState(-1);
  const [selectedDm, setSelectedDm] = React.useState(-1);
  const [selectedChDm, setSelectedChDm] = React.useState('');
  const [channelsShare, setChannelsShare] = React.useState([]);
  const [dmsShare, setDmsShare] = React.useState([]);
  const [message, setMessage] = React.useState('');

  const token = React.useContext(AuthContext);

  const step = useStep();

  function fetchChannelData() {
    axios
      .get('channels/list/v2', {
        params: {
          token,
        },
      })
      .then(({ data }) => {
        setChannelsShare(data['channels']);
      })
      .catch((err) => { });
    axios
      .get('dm/list/v1', {
        params: {
          token,
        },
      })
      .then(({ data }) => {
        setDmsShare(data['dms']);
      })
      .catch((err) => { });
  }

  React.useEffect(() => {
    fetchChannelData();
  }, []);

  const handleChannelSelect = event => {
    setSelectedChDm(event.target.value);
    if (event.target.value.slice(0, 1) === 'd') {
      setSelectedDm(event.target.value.slice(1));
      setSelectedChannel(-1);
    } else {
      setSelectedChannel(event.target.value.slice(1));
      setSelectedDm(-1);
    }
  };

  function handleClickOpen() {
    setOpen(true);
  }

  function handleClose() {
    setOpen(false);
  }

  const handleChange = (event) => {
    setMessage(event.target.value);
  };

  function handleSubmit(event) {
    event.preventDefault();

    axios.post(`/message/share/v1`, {
      token,
      og_message_id: Number.parseInt(og_message_id),
      message,
      channel_id: Number.parseInt(selectedChannel),
      dm_id: Number.parseInt(selectedDm),
    })
      .then((response) => {
        console.log(response);
        step();
      })
      .catch((err) => { });
  }
  return (
    <div>
      <IconButton
        onClick={handleClickOpen}
        style={{ margin: 1 }}
        size="small"
        edge="end"
        aria-label="share"
      >
        <ArrowForwardIcon fontSize="small" />
      </IconButton>
      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="form-dialog-title"
      >
        <DialogTitle id="form-dialog-title">Share message</DialogTitle>
        <form onSubmit={handleSubmit}>
          <DialogContent>
            <DialogContentText>
              Enter a channel below to share the message to
            </DialogContentText>
            <Select style={{ width: "100%" }} id="u_id" onChange={handleChannelSelect} value={selectedChDm}>
              {channelsShare.map((d) => {
                return <MenuItem key={d.channel_id} value={`c${d.channel_id}`}>{d.name}</MenuItem>
              })}
              {dmsShare.map((d) => {
                return <MenuItem key={d.dm_id} value={`d${d.dm_id}`}>{d.name}</MenuItem>
              })}
            </Select>
            <br /><br />
            <DialogContentText>
              Optionally, enter an additional message
            </DialogContentText>
            <TextField
              multiline
              fullWidth
              rowsMax={4}
              value={message}
              onChange={handleChange}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={handleClose} color="primary">
              Cancel
            </Button>
            <Button onClick={handleClose} type="submit" color="primary">
              Share
            </Button>
          </DialogActions>
        </form>
      </Dialog>
    </div>
  );
}

export default MessageShareDialog;
