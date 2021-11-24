import {CircularProgress} from "@material-ui/core";
import React from "react";

function Placeholder() {
    return <div style={{
        display: "flex",
        width: "100%",
        height: "100%",
        justifyContent: "center",
        alignItems: "center"
    }}>
        <CircularProgress />
    </div>;
}

export default Placeholder;
