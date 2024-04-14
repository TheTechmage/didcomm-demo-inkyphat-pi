# didcomm-demo-inkyphat-pi
A demo of using DIDComm on a Raspberry Pi connected to an inkyphat e-ink
display.

This project was set up to demonstrate using DIDComm on a Raspberry Pi at IIW,
April 2024. I had some inspiration to set this up a couple of weeks before IIW
and just hacked away at it in the middle of the night so if the code looks bad,
that's why. I haven't really spent the time polishing it up, I've been more
focused on "Get the demo working".

The application runs as a "service" on a Raspberry Pi (specifically tested on a
Raspberry Pi Zero W) and it works by connecting to the Indicio Internal
Development Mediator (That just happens to be the one I'm used to),
establishing mediation, and accepting protocol-specific DIDComm messages meant
for changing the Inky pHat e-ink display to show a name tag for the name
provided in the DIDComm message. To demonstrate messages going from the Pi to
another agent (effectively, demonstrating bi-directional communication), 2 HTTP
API calls are exposed. These are attached to the power button on the PiSugar 2
which is connected to my Pi. If I push the power button, the PiSugar software
sends an HTTP request to either of these two endpoints, which then trigger a
DIDComm message to be sent to the last party who communicated with us.

## How to get things running

### Requirements
The following software and hardware are required to get this project running:

Hardware:
- Raspberry Pi Zero W
- Inky pHat

Software:
- [Git](https://git-scm.com/)
- [PDM](https://pdm-project.org/en/latest/)
- [inky](https://learn.pimoroni.com/article/getting-started-with-inky-phat)

While the pHat is required *for this project*, there are many IoT use cases
that can be accomplished outside of just changing a name tag.

### Running the service
To simplify the process, I've included a pre-built package of Aries Askar, as
well as PDM project files. After cloning the project, the following should be
sufficient to launch the application:

```bash
pdm install
pdm run python src/__main__.py
```
