import React from 'react';
import Edit from '@material-ui/icons/Edit';
import Cancel from '@material-ui/icons/Cancel';
import Save from '@material-ui/icons/Save';
import { Grid } from '@material-ui/core';

function EditableFields({
  editable,
  master,
  masterValue,
  slaves,
  slaveValues,
  onSave,
  ...props
}) {

  const [edit, setEdit] = React.useState(false);
  const [prevMasterValue, setPrevMasterValue] = React.useState();
  const [currMasterValue, setCurrMasterValue] = React.useState(masterValue);
  const [prevSlaveValues, setPrevSlaveValues] = React.useState([]);
  const [currSlaveValues, setCurrSlaveValues] = React.useState(slaveValues);

  // Handle async passing of master/slave values
  React.useEffect(() => {
    setCurrMasterValue(masterValue);
    setCurrSlaveValues(slaveValues);
  }, [masterValue, slaveValues]);

  function toggleEdit() {
    setPrevMasterValue(currMasterValue);
    setPrevSlaveValues(currSlaveValues);
    setEdit(!edit);
  }

  function icons() {
    if (!editable) return null;
    if (edit) {
      return (
        <>
          <Save
            style={{ cursor: 'pointer' }}
            onClick={() => {
              if (currMasterValue == null) return;
              if (onSave) {
                if (currSlaveValues) {
                  onSave(currMasterValue, ...currSlaveValues);
                } else {
                  onSave(currMasterValue);
                }
              }
              toggleEdit();
            }}
          />
          <Cancel
            style={{ cursor: 'pointer' }}
            onClick={() => {
              setCurrMasterValue(prevMasterValue);
              setCurrSlaveValues(prevSlaveValues);
              toggleEdit();
            }}
          />
        </>
      );
    }
    return <Edit style={{ cursor: 'pointer' }} onClick={toggleEdit} />;
  }
  function onSlaveChange(event, valueIndex) {
    let copySlaves = currSlaveValues.map((val, idx) => {
      if (idx === valueIndex) return event.target.value;
      return val;
    });
    setCurrSlaveValues(copySlaves);
  }

  function onMasterChange(event) {
    setCurrMasterValue(event.target.value);
  }

  return (
    <Grid container spacing={1} alignItems="flex-end">
      {slaves &&
        slaves.map((slave, idx) => {
          return (
            <Grid item key={idx}>
              {slave({
                value: currSlaveValues[idx] || "", // "" required for label placeholder mechanics
                InputProps: { readOnly: !edit },
                onChange: (event) => onSlaveChange(event, idx),
              })}
            </Grid>
          );
        })}
      <Grid item>
        {master({
          value: currMasterValue || "", // "" required for label placeholder mechanics
          InputProps: { readOnly: !edit },
          onChange: onMasterChange,
        })}
      </Grid>
      {editable && <Grid item>{icons()}</Grid>}
    </Grid>
  );
}

export default EditableFields;
