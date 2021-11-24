import {
  List,
  ListItem,
  ListSubheader,
  TextField,
  Typography,
} from '@material-ui/core';
import axios from 'axios';
import React from 'react';
import AuthContext from '../../AuthContext';
import { extractUId } from '../../utils/token';
import EditableFields from './EditableFields';
import UserStats from './UserStats';
import Placeholder from '../Placeholder';

function Profile({ profile }) {

  const [loading, setLoading] = React.useState(true);
  const [profileDetails, setProfileDetails] = React.useState({});
  const token = React.useContext(AuthContext);
  const u_id = extractUId(token);

  React.useEffect(() => {
    axios
      .get(`/user/profile/v1`, { params: { token, u_id: profile } })
      .then(({ data }) => {
        console.log(data);
        const { user } = data;
        setProfileDetails(user);
      })
      .catch((err) => {
        console.error(err);
      })
      .finally(() => setLoading(false));
  }, [profile, token]);

  function updateName(name_last, name_first) {
    axios
      .put(`/user/profile/setname/v1`, { token, name_first, name_last })
      .then(() => {
        console.log('all good');
      })
      .catch((err) => {
        console.error(err);
      });
  }

  function updateEmail(email) {
    axios
      .put(`/user/profile/setemail/v1`, { token, email })
      .then(() => {
        console.log('all good');
      })
      .catch((err) => {
        console.error(err);
      });
  }

  function updateProfileImgUrl(raw_text) {
    const items = raw_text.split(',');
    axios
      .post(`/user/profile/uploadphoto/v1`, {
        token,
        img_url: items[0],
        x_start: Number.parseInt(items[1]),
        y_start: Number.parseInt(items[2]),
        x_end: Number.parseInt(items[3]),
        y_end: Number.parseInt(items[4]),
      })
      .then(() => {
        console.log('all good');
      })
      .catch((err) => {
        console.error(err);
      });
  }

  function updateHandle(handle_str) {
    axios
      .put(`/user/profile/sethandle/v1`, { token, handle_str })
      .then(() => {
        console.log('all good');
      })
      .catch((err) => {
        console.error(err);
      });
  }

  const editable = u_id.toString() === profile;

  return (
    <>
      <Typography variant="h4">Profile</Typography>
      {loading
        ? <Placeholder />
        : <List subheader={<ListSubheader>Profile Details</ListSubheader>}>
          <ListItem key={'name'}>
            <EditableFields
              editable={editable}
              masterValue={profileDetails.name_last}
              slaveValues={[profileDetails.name_first]}
              master={(passed_props) => (
                <TextField label={'Last Name'} {...passed_props} />
              )}
              slaves={[
                (passed_props) => (
                  <TextField label={'First Name'} {...passed_props} />
                ),
              ]}
              onSave={updateName}
            />
          </ListItem>
          <ListItem key={'email'}>
            <EditableFields
              editable={editable}
              masterValue={profileDetails.email}
              master={(passed_props) => (
                <TextField label={'Email'} {...passed_props} />
              )}
              onSave={updateEmail}
            />
          </ListItem>
          <ListItem key={'handle'}>
            <EditableFields
              editable={editable}
              masterValue={profileDetails.handle_str}
              master={(passed_props) => (
                <TextField label={'Handle'} {...passed_props} />
              )}
              onSave={updateHandle}
            />
          </ListItem>
          <ListItem key={'img_url'}>
            <EditableFields
              editable={editable}
              masterValue={profileDetails.profile_img_url}
              master={(passed_props) => (
                <TextField label={'img_url,x1,y1,x2,y2'} {...passed_props} />
              )}
              onSave={updateProfileImgUrl}
            />
          </ListItem>
          <br />
          <div>
            NOTE: The final field input is to set a profile image. Please enter the 5 components (image url,
            x_start, y_start, x_end, y_end) separated by commas.
          </div>
        </List>
      }
      <br />
      {editable && <UserStats />}
    </>
  );
}

export default Profile;
