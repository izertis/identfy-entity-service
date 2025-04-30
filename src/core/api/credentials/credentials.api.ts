import {Request, Response} from 'express';
import {autoInjectable, singleton} from 'tsyringe';
import {
  IBasicCredential_req,
  ICredential_req,
  IDirectEbsiAccreditationIssuanceRequest,
  IStatusCredentialRequest,
} from '../../../shared/interfaces/credentials.interface.js';
import Logger from '../../../shared/classes/logger.js';
import {UnauthorizedError} from '../../../shared/classes/error/httperrors.js';
import CredentialsService from '../../services/credentials/credentials.service.js';

@singleton()
@autoInjectable()
export default class CredentialsApi {
  constructor(
    private credentialsService: CredentialsService,
    private logger: Logger,
  ) {}

  credentialRequest = async (req: Request, res: Response) => {
    this.logger.info('Credential request received...');
    const bearer = req.headers.authorization;
    if (!bearer)
      throw new UnauthorizedError(
        'No access token provided',
        'unauthorized_client',
      );
    const {
      issuerUri,
      issuerDid,
      listId,
      listIndex,
      listProxy,
      ...request
    } = req.body as ICredential_req;
    const {status, ...response} = await this.credentialsService.issueCredential(
      bearer.replace('Bearer ', ''), // https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
      request,
      issuerUri,
      issuerDid,
      listId,
      listIndex,
      listProxy,
    );
    this.logger.info('✅ Returning Credential response');
    return res.status(status).json(response);
  };

  deferredCredentialRequest = async (req: Request, res: Response) => {
    this.logger.info('Deferred Credential request received...');
    const bearer = req.headers.authorization;
    if (!bearer)
      throw new UnauthorizedError(
        'No access token provided',
        'unauthorized_client',
      );
    const {issuerUri, issuerDid} =
      req.body as IBasicCredential_req;
    const {status, ...response} =
      await this.credentialsService.issueDeferredCredential(
        bearer.replace(/Bearer|\s/g, ''), // remove BEARER and " " spaces
        issuerUri,
        issuerDid,
      );
    this.logger.info('✅ Returning Deferred Credential response');
    return res.status(status).json(response);
  };

  statusCredentialRequest = async (req: Request, res: Response) => {
    this.logger.info('Status Credential request received...');
    const {
      issuerDid,
      issuerUri,
      listId,
      statusList,
      statusPurpose,
      revocationType,
    } = req.body as IStatusCredentialRequest;
    const {status, ...response} = await this.credentialsService.issueStatusVC(
      issuerDid,
      issuerUri,
      listId,
      statusList,
      statusPurpose,
      revocationType,
    );
    this.logger.info('✅ Returning Status Credential response');
    return res.status(status).send(response.credential);
  };

  ebsiAccreditationDirectIssuance = async (req: Request, res: Response) => {
    this.logger.info('Direct EBSI Accreditation Issuance request received...');
    const {accreditationType, holderDid, issuerUri, issuerDid} =
      req.query as unknown as IDirectEbsiAccreditationIssuanceRequest;
    const {status, ...response} =
      await this.credentialsService.ebsiDirectAccreditationIssuance(
        accreditationType,
        holderDid,
        issuerUri,
        issuerDid,
      );
    this.logger.info('✅ Returning EBSI Accreditation Credential response');
    return res.status(status).json(response);
  };
}
