import React from 'react';
import {createRoot} from 'react-dom/client';
import {Workspace} from '../../stitch_intentlock_operator_console/operator_live/Workspace';
/** The runtime mounts the user-selected Stitch workspace, without a second design implementation. */
createRoot(document.getElementById('root')!).render(<React.StrictMode><Workspace/></React.StrictMode>);
