import axios from 'axios';
import React from 'react';
import { Scatter } from "react-chartjs-2";
import { Typography } from '@material-ui/core';
import AuthContext from '../../AuthContext';

function UserStats() {

  const token = React.useContext(AuthContext);
  const [involvementRate, setInvolvementRate] = React.useState(0);
  const [channelsData, setChannelsData] = React.useState([]);
  const [dmsData, setDmsData] = React.useState([]);
  const [messagesData, setMessagesData] = React.useState([]);

  React.useEffect(() => {
    axios
      .get(`/user/stats/v1`, { params: { token } })
      .then(({ data }) => {
        console.log(data);
        const { user_stats } = data;
        setInvolvementRate(user_stats['involvement_rate']);
        setChannelsData(user_stats['channels_joined'].map((obj) => {
          return { x: new Date(obj['time_stamp'] * 1000), y: obj['num_channels_joined'] };
        }));
        setDmsData(user_stats['dms_joined'].map((obj) => {
          return { x: new Date(obj['time_stamp'] * 1000), y: obj['num_dms_joined'] };
        }));
        setMessagesData(user_stats['messages_sent'].map((obj) => {
          return { x: new Date(obj['time_stamp'] * 1000), y: obj['num_messages_sent'] };
        }));
      })
      .catch((err) => {
        console.error(err);
      })
  }, [token]);

  return (
    <>
      <Typography variant="h5">User statistics</Typography>
      <p>Involvement rate: {(involvementRate * 100).toFixed(2)}%</p>
      <Scatter
        data={{
          datasets: [
            {
              label: "Channels joined",
              data: channelsData,
              fill: false,
              borderColor: "#742774",
              showLine: true,
            },
            {
              label: "Dms joined",
              data: dmsData,
              fill: false,
              borderColor: "#4287f5",
              showLine: true,
            },
            {
              label: "Messages sent",
              data: messagesData,
              fill: false,
              borderColor: "#bd2d4f",
              showLine: true,
            },
          ]
        }}
        options={{
          scales: {
            xAxes: [{
              title: "time",
              type: 'time',
              gridLines: {
                lineWidth: 2
              },
              time: {
                unitStepSize: 200,
                displayFormats: {
                  millisecond: 'MMM DD HH:mm',
                  second: 'MMM DD HH:mm',
                  minute: 'MMM DD HH:mm',
                  hour: 'MMM DD HH:mm',
                  day: 'MMM DD',
                  week: 'MMM DD',
                  month: 'MMM DD',
                  quarter: 'MMM DD',
                  year: 'MMM DD',
                }
              }
            }]
          }
        }}
      />
    </>
  );
}

export default UserStats;
