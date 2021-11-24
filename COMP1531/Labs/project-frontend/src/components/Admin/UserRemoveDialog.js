import React from "react";
import axios from 'axios';
import {
  Dialog,
  DialogTitle,
  DialogActions,
  DialogContent,
  DialogContentText,
  Button,
  Grid,
  MenuItem,
  Select,
} from "@material-ui/core";
import AuthContext from "../../AuthContext";

function UserRemoveDialog({ children, ...props }) {

  const [open, setOpen] = React.useState(false);
  const [users, setUsers] = React.useState([]);
  const [selectedUser, setSelectedUser] = React.useState('');
  const token = React.useContext(AuthContext);

  React.useEffect(() => {
    function fetchUserData() {
      axios
        .get('/users/all/v1', {
          params: {
            token,
          },
        })
        .then(({ data }) => {
          setUsers(data['users']);
        })
        .catch((err) => { });
    }

    fetchUserData();
  }, []);

  const handleUserSelect = event => {
    const newUserId = parseInt(event.target.value, 10);
    setSelectedUser(newUserId);
  };

  function handleClickOpen() {
    setOpen(true);
  }

  function handleClose() {
    setOpen(false);
  }

  function handleSubmit(event) {
    event.preventDefault();

    if (!event.target[0].value) return;

    const u_id = parseInt(event.target[0].value, 10);

    axios
      .delete(`/admin/user/remove/v1`, {
        data: {
          token,
          u_id: Number.parseInt(u_id),
        }
      })
      .then(response => {
        console.log(response);
      })
      .catch(err => { });
  }

  return <>
    <div onClick={handleClickOpen}>
      {children}
    </div>
    <Dialog
      open={open}
      onClose={handleClose}
      aria-labelledby="form-dialog-title"
    >
      <DialogTitle id="form-dialog-title">Remove Users</DialogTitle>
      <form onSubmit={handleSubmit}>
        <DialogContent>
          <DialogContentText>
            Select a user below to remove
          </DialogContentText>
          <Grid
            container
            spacing={2}
            direction="row"
            justify="center"
            alignItems="center"
          >
            <Grid item xs={12}>
              <Select style={{ width: "100%" }} id="u_id" onChange={handleUserSelect} value={selectedUser}>
                {users.map((d, idx) => {
                  return <MenuItem key={d.u_id} value={d.u_id}>{d.name_first} {d.name_last}</MenuItem>
                })}
              </Select>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose} color="primary">
            Cancel
          </Button>
          <Button onClick={handleClose} type="submit" color="primary">
            Remove
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  </>;
}

export default UserRemoveDialog;
