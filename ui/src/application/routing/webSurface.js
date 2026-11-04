import routes from '../../../../contracts/web-surface-routes.json';
import { validateWebSurfaceContract, webPathOwner } from './webSurfaceContract.mjs';

export const WEB_SURFACE_ROUTES = validateWebSurfaceContract(routes);
export const getWebSurface = (pathname) => webPathOwner(pathname, WEB_SURFACE_ROUTES);
