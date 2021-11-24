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
  FormControlLabel,
  RadioGroup,
  Radio,
  MenuItem,
  Select,
} from "@material-ui/core";
import AuthContext from "../../AuthContext";
import { PERMISSION_IDS } from "../../utils/constants";

function SetUserPermissionsDialog({ children, ...props }) {

  const [open, setOpen] = React.useState(false);
  const [permissionId, setPermissionId] = React.useState(PERMISSION_IDS.MEMBER);
  const [users, setUsers] = React.useState([]);
  const [selectedUser, setSelectedUser] = React.useState('');
  const token = React.useContext(AuthContext);

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

  React.useEffect(() => {
    fetchUserData();
  }, []);


  const handleRadioChange = event => {
    const newPermissionId = parseInt(event.target.value, 10);
    setPermissionId(newPermissionId);
  };

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
    const permission_id = parseInt(permissionId, 10);

    axios
      .post(`/admin/userpermission/change/v1`, {
        token,
        u_id: Number.parseInt(u_id),
        permission_id: Number.parseInt(permission_id),
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
      <DialogTitle id="form-dialog-title">Set User Permissions</DialogTitle>
      <form onSubmit={handleSubmit}>
        <DialogContent>
          <DialogContentText>
            Select a user below to set permissions for this user
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
            <Grid container item justify="center" alignItems="center">
              <RadioGroup aria-label="position" name="position" value={permissionId} onChange={handleRadioChange} row>
                <FormControlLabel
                  value={PERMISSION_IDS.MEMBER}
                  control={<Radio color="primary" />}
                  label="Member"
                  labelPlacement="bottom"
                />
                <FormControlLabel
                  value={PERMISSION_IDS.OWNER}
                  control={<Radio color="primary" />}
                  label="Owner"
                  labelPlacement="bottom"
                />
              </RadioGroup>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose} color="primary">
            Cancel
                    </Button>
          <Button onClick={handleClose} type="submit" color="primary">
            Set
                    </Button>
        </DialogActions>
      </form>
    </Dialog>
  </>;
}

export default SetUserPermissionsDialog;
