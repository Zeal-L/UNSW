import React from 'react';
import axios from 'axios';

import {
  Badge,
  IconButton,
} from '@material-ui/core';

import ThumbUpIcon from '@material-ui/icons/ThumbUp';
import ThumbUpOutlinedIcon from '@material-ui/icons/ThumbUpOutlined';

import AuthContext from '../../AuthContext';
import { StepContext } from '../Channel/ChannelMessages';
import { StepContextDm } from '../Dm/DmMessages';

function MessageReact({
  message_id,
  reacts = [] /* [{ react_id, u_ids }] */,
}) {

  const token = React.useContext(AuthContext);
  let step = React.useContext(StepContext);
  let stepDm = React.useContext(StepContextDm);
  step = step ? step : () => { }; // sanity check
  stepDm = stepDm ? stepDm : () => { }; // sanity check

  const messageReact = (is_reacted) => {
    if (is_reacted) {
      axios.post(`/message/unreact/v1`, {
        token,
        message_id: Number.parseInt(message_id),
        react_id: 1 /* FIXME */,
      })
        .then(() => {
          step();
          stepDm();
        });
    } else {
      axios.post(`/message/react/v1`, {
        token,
        message_id: Number.parseInt(message_id),
        react_id: 1 /* FIXME */,
      })
        .then(() => {
          step();
          stepDm();
        });
    }
  };

  let thumbUpCount = 0;
  let is_reacted = false;
  const thumbUpIndex = reacts.findIndex((react) => react.react_id === 1);
  if (thumbUpIndex !== -1) {
    thumbUpCount = reacts[thumbUpIndex].u_ids.length;
    is_reacted = reacts[thumbUpIndex].is_this_user_reacted;
  }

  return (
    <Badge
      anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      badgeContent={thumbUpCount}
      color="secondary"
    >
      <IconButton
        onClick={() => messageReact(is_reacted)}
        style={{ margin: 1 }}
        size="small"
        edge="end"
        aria-label="delete"
      >
        {is_reacted ? (
          <ThumbUpIcon fontSize="small" />
        ) : (
          <ThumbUpOutlinedIcon fontSize="small" />
        )}
      </IconButton>
    </Badge>
  );
}

export default MessageReact;
