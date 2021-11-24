import React from 'react';

import Button from '@material-ui/core/Button';
import ButtonGroup from '@material-ui/core/ButtonGroup';
import ArrowDropDownIcon from '@material-ui/icons/ArrowDropDown';
import ClickAwayListener from '@material-ui/core/ClickAwayListener';
import Grow from '@material-ui/core/Grow';
import Paper from '@material-ui/core/Paper';
import Popper from '@material-ui/core/Popper';
import MenuItem from '@material-ui/core/MenuItem';
import MenuList from '@material-ui/core/MenuList';
import { getIsPolling, setIsPolling, step, usePolling } from '../../utils/update';

const options = ['Live', 'Step'];

function PollToggle() {

    const [open, setOpen] = React.useState(false);
    const anchorRef = React.useRef(null);
    const [selectedIndex, setSelectedIndex] = React.useState(getIsPolling() ? 0 : 1);

    usePolling();

    const handleClick = () => {
        step();
    };

    const handleMenuItemClick = (event, index) => {
        setIsPolling(index === 0);
        setSelectedIndex(index);
        setOpen(false);
    };

    const handleToggle = () => {
        setOpen(prevOpen => !prevOpen);
    };

    const handleClose = event => {
        if (anchorRef.current && anchorRef.current.contains(event.target)) {
            return;
        }
        setOpen(false);
    };

    return (<>
        <ButtonGroup
            variant="contained"
            color="primary"
            ref={anchorRef}
            aria-label="split button"
            style={{marginRight: 15}}
        >
            <Button onClick={handleClick} disabled={selectedIndex === 0}>{options[selectedIndex]}</Button>
            <Button
            color="primary"
            size="small"
            aria-owns={open ? 'menu-list-grow' : undefined}
            aria-haspopup="true"
            onClick={handleToggle}
            >
            <ArrowDropDownIcon />
            </Button>
        </ButtonGroup>
        <Popper open={open} anchorEl={anchorRef.current} transition disablePortal>
            {({ TransitionProps, placement }) => (
            <Grow
                {...TransitionProps}
                style={{
                transformOrigin: placement === 'bottom' ? 'center top' : 'center bottom',
                }}
            >
                <Paper id="menu-list-grow">
                <ClickAwayListener onClickAway={handleClose}>
                    <MenuList>
                    {options.map((option, index) => (
                        <MenuItem
                        key={option}
                        disabled={index === 2}
                        selected={index === selectedIndex}
                        onClick={event => handleMenuItemClick(event, index)}
                        >
                        {option}
                        </MenuItem>
                    ))}
                    </MenuList>
                </ClickAwayListener>
                </Paper>
            </Grow>
            )}
        </Popper>
    </>);
}

export default PollToggle;