import axios from 'axios';
import {
  Avatar,
  Box,
  Button,
  Container,
  Grid,
  Link,
  makeStyles,
  TextField,
  Typography,
} from '@material-ui/core';
import DeveloperOutlinedIcon from '@material-ui/icons/DeveloperModeOutlined';
import React from 'react';
import Placeholder from "../components/Placeholder";

const useStyles = makeStyles((theme) => ({
  '@global': {
    body: {
      backgroundColor: theme.palette.primary.light,
    },
  },
  card: {
    backgroundColor: theme.palette.background.paper,
    marginTop: theme.spacing(8),
    padding: theme.spacing(8),
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    borderRadius: theme.shape.borderRadius,
  },
}));

function ForgotPasswordPage(props) {
  const [loading, setLoading] = React.useState(false);

  function handleSubmit(event) {
    event.preventDefault();

    // Get user inputs (TODO:)
    const email = event.target[0].value;

    // Quick validation
    if (!email) return;

    setLoading(true);

    // Send to backend
    axios.post(`/auth/passwordreset/request/v1`, { email })
      .then((response) => {
        console.log(response);
        props.history.push('/reset_password');
      })
      .catch((err) => { })
      .finally(() => setLoading(false));
  }

  const classes = useStyles();

  return (
    <Container component="main" maxWidth="sm">
      <Box boxShadow={3} className={classes.card}>
        <Avatar>
          <DeveloperOutlinedIcon color="secondary" />
        </Avatar>
        <Typography component="h1" variant="h5">
          Forgot Password
        </Typography>
        {
          loading
            ? <div style={{ marginTop: "64px" }}><Placeholder /></div>
            : <form noValidate onSubmit={handleSubmit}>
              <TextField
                variant="outlined"
                margin="normal"
                required
                fullWidth
                id="email"
                label="Email"
                name="email"
                type="email"
                autoFocus
              />
              <Button type="submit" fullWidth variant="contained" color="primary">
                Send Recovery Email
                </Button>
              <Grid container>
                <Grid item>
                  <br />
                  <Link href="/login" variant="body1">
                    {'Remember your password? Login'}
                  </Link>
                </Grid>
              </Grid>
            </form>
        }
      </Box>
    </Container>
  );
}

export default ForgotPasswordPage;
