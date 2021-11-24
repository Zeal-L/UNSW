import axios from 'axios';
import React from 'react';
import { Scatter } from "react-chartjs-2";
import { Typography } from '@material-ui/core';
import AuthContext from '../AuthContext';

function WorkspaceStats() {

  const token = React.useContext(AuthContext);
  const [utilizationRate, setUtilizationRate] = React.useState(0);
  const [channelsData, setChannelsData] = React.useState([]);
  const [dmsData, setDmsData] = React.useState([]);
  const [messagesData, setMessagesData] = React.useState([]);

  React.useEffect(() => {
    axios
      .get(`/users/stats/v1`, { params: { token } })
      .then(({ data }) => {
        console.log(data);
        const { workspace_stats } = data;
        setUtilizationRate(workspace_stats['utilization_rate']);
        setChannelsData(workspace_stats['channels_exist'].map((obj) => {
          return { x: new Date(obj['time_stamp'] * 1000), y: obj['num_channels_exist'] };
        }));
        setDmsData(workspace_stats['dms_exist'].map((obj) => {
          return { x: new Date(obj['time_stamp'] * 1000), y: obj['num_dms_exist'] };
        }));
        setMessagesData(workspace_stats['messages_exist'].map((obj) => {
          return { x: new Date(obj['time_stamp'] * 1000), y: obj['num_messages_exist'] };
        }));
      })
      .catch((err) => {
        console.error(err);
      })
  }, [token]);

  return (
    <>
      <Typography variant="h5">Workspace statistics</Typography>
      <p>Wow! {(utilizationRate * 100).toFixed(2)}% utilisation</p>
      <Scatter
        data={{
          datasets: [
            {
              label: "Channels",
              data: channelsData,
              fill: false,
              borderColor: "#742774",
              showLine: true,
            },
            {
              label: "Dms",
              data: dmsData,
              fill: false,
              borderColor: "#4287f5",
              showLine: true,
            },
            {
              label: "Messages",
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

export default WorkspaceStats;
