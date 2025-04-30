<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./docs/img/identfy-logo-dark.svg">
      <source media="(prefers-color-scheme: light)" srcset="./docs/img/identfy-logo-light.svg">
      <img alt="identfy" src="./docs/img/identfy.png" width="350" style="max-width: 100%;">
    </picture>
</p>

<p align="center">
  <h4>
    An all-in-one solution to take control of your digital identity
  </h4>
</p>

<br/>

**[identfy](https://github.com/izertis/identfy)** is a combination of various products that enable building user-centric solutions.

# identfy Entity service

This repository contains an implementation of a stateless service that allows the issuance of verifiable credentials compatible with EBSI guidelines and in *jwt_vc* format. The service also serves as an authorization server.

## Table of content:

- [How to start using it](#usage)
- [Development guide](#development-guide)
- [License](#license)
- [Trademark](#trademark)


## Usage

The execution of the service can be done through docker or through its direct execution.

### Minimun ENV Configuration

The minimun set of variables needed in order to execute the service are the following ones:
- **BACKEND_URL**: URL of the Identfy BackOffice component.
- **BACKEND_USER**: Username used by the service to authenticate with the BackOffice component.
- **BACKEND_PASS**: Password used by the service to authenticate with the BackOffice component.
- **NODE_CONFIG_DIR**: Path to the configuration files of this component (e.g., deploy/config).
- **NODE_ENV**: Name of the specific configuration file to load from the configuration path, e.g., "local" to load the `local.yaml` file.

### Node Execution

Node version 22 is required to operate the service.

Clone the repository and install the dependencies with:

`npm install`

Run the server with:

`npm run serve`


### Docker

Clone the repository and create an image for the service using the Dockerfile located in the root of the project.
`docker build . -t identfy-service`

Once the docker image is created, you can deploy a container by specifying the desired configuration. In the case of requiring configuration by file, the dockerfile will include the files indicated in the "deploy" directory, so you can modify them if desired. Additionally, it is also possible to mount a volume and host the configuration files in it.

### Docker-compose

Clone the repository and use docker-compose to create a container of the service using the file located in the `deploy` directory. You do not need to create the image first, as it is configured to do so. To do so, run the following command:

`docker-compose up`


## Development guide

If you are interested on testing and building it by yourself or you would like to contribute, you can find here the [development guide](./docs/GETTING_STARTED.md)


## Help and Documentation

- *Contact:* send an email to blockchain@izertis.com
- [Github discussions](https://github.com/izertis/identfy-entity-service/discussions) - Help and general questions about this project


# License
This software is dual-licensed; you can choose between the terms of the [Affero GNU General Public License version 3 (AGPL-3.0)](./LICENSES/agpl-3.0.txt) or a [commercial license](./LICENSES/commercial.txt). Look at [LICENSE](./LICENSE.md) file for more information.


# Trademark
**identfy** and its logo are registered trademarks of [Izertis](https://www.izertis.com)
