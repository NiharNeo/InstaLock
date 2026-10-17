import React from 'react';
import {createRoot} from 'react-dom/client';
import {Storefront} from '../../stitch_intentlock_operator_console/operator_live/Storefront';
import {Workspace} from '../../stitch_intentlock_operator_console/operator_live/Workspace';
/** The runtime mounts the user-selected Stitch workspace, without a second design implementation. */
createRoot(document.getElementById('root')!).render(<React.StrictMode>{location.pathname.startsWith('/store/')||location.pathname==='/store'?<Storefront/>:<Workspace/>}</React.StrictMode>);
