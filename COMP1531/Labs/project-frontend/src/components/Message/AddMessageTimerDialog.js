import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from '@material-ui/core';
import { KeyboardTimePicker } from '@material-ui/pickers';
import React from 'react';

function AddMessageTimerDialog({ open, handleClose, onTimerChange, ...props }) {
  const [selectedDate, setSelectedDate] = React.useState(new Date());

  function handleSubmit(event) {
    event.preventDefault();
    onTimerChange(selectedDate);
  }

  return (
    <div>
      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="form-dialog-title"
      >
        <DialogTitle id="form-dialog-title">Send later</DialogTitle>
        <form onSubmit={handleSubmit}>
          <DialogContent>
            <KeyboardTimePicker
              margin="normal"
              id="time-picker"
              label="Time picker"
              value={selectedDate}
              onChange={(d) => setSelectedDate(d.toDate())}
              KeyboardButtonProps={{
                'aria-label': 'change time',
              }}
            />
            <DialogContentText>Enter a time to send</DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleClose} color="primary">
              Cancel
            </Button>
            <Button onClick={handleClose} type="submit" color="primary">
              Set Time
            </Button>
          </DialogActions>
        </form>
      </Dialog>
    </div>
  );
}

export default AddMessageTimerDialog;
