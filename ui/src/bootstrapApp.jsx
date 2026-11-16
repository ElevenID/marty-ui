import { get, post } from './services/api';
import { configureCommerceApi } from './extensions/commerce';

configureCommerceApi({ get, post });
export { mountApp } from './bootstrapRoot';
