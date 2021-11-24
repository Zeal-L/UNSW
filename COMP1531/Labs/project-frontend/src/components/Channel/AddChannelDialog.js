import React from "react";
import axios from 'axios';
import {
  Dialog,
  DialogTitle,
  DialogActions,
  DialogContent,
  DialogContentText,
  IconButton,
  Button,
  Switch,
  TextField,
  Grid,
  FormControlLabel,
} from "@material-ui/core";
import Visibility from "@material-ui/icons/Visibility";
import VisibilityOff from "@material-ui/icons/VisibilityOff";
import Add from "@material-ui/icons/Add";
import AuthContext from "../../AuthContext";

function AddChannelDialog({ ...props }) {
  const [open, setOpen] = React.useState(false);
  const token = React.useContext(AuthContext);
  function handleClickOpen() {
    setOpen(true);
  }
  function handleClose() {
    setOpen(false);
  }
  function handleSubmit(event) {
    event.preventDefault();
    const name = event.target[0].value;
    const secret = event.target[1].checked;
    const is_public = !secret;

    if (!name) return;

    axios
      .post(`/channels/create/v2`, { token, name, is_public })
      .then(response => {
        console.log(response);
        props.callback();
      })
      .catch(err => { });
  }
  return (
    <div>
      <IconButton size="small" onClick={handleClickOpen}>
        <Add />
      </IconButton>
      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="form-dialog-title"
      >
        <DialogTitle id="form-dialog-title">Create Channel</DialogTitle>
        <form onSubmit={handleSubmit}>
          <DialogContent>
            <DialogContentText>
              Complete the form below to create a new channel
            </DialogContentText>
            <Grid
              container
              spacing={2}
              direction="row"
              justify="center"
              alignItems="center"
            >
              <Grid item xs={12}>
                <TextField
                  autoFocus
                  margin="dense"
                  id="channel_name"
                  label="Channel Name"
                  name="channel_name"
                  fullWidth
                />
              </Grid>
              <Grid container item justify="center" alignItems="center">
                <Visibility />
                <FormControlLabel
                  control={
                    <Switch
                      value="secret"
                      inputProps={{ "aria-label": "Secret" }}
                    />
                  }
                  label="Secret"
                  labelPlacement="top"
                />
                <VisibilityOff />
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleClose} color="primary">
              Cancel
            </Button>
            <Button onClick={handleClose} type="submit" color="primary">
              Create
            </Button>
          </DialogActions>
        </form>
      </Dialog>
    </div>
  );
}

export default AddChannelDialog;
