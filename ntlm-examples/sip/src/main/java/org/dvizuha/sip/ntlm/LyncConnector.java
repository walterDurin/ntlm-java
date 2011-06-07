/*
 * $Id: $
 */
package org.dvizuha.sip.ntlm;

import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.microsoft.security.ntlm.NtlmAuthenticator;
import org.microsoft.security.ntlm.NtlmSession;
import org.microsoft.security.ntlm.impl.Algorithms;

import javax.sip.ClientTransaction;
import javax.sip.Dialog;
import javax.sip.DialogTerminatedEvent;
import javax.sip.IOExceptionEvent;
import javax.sip.ListeningPoint;
import javax.sip.PeerUnavailableException;
import javax.sip.RequestEvent;
import javax.sip.ResponseEvent;
import javax.sip.ServerTransaction;
import javax.sip.SipFactory;
import javax.sip.SipListener;
import javax.sip.SipProvider;
import javax.sip.SipStack;
import javax.sip.TransactionTerminatedEvent;
import javax.sip.address.Address;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.header.AcceptHeader;
import javax.sip.header.AuthorizationHeader;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.header.ContactHeader;
import javax.sip.header.EventHeader;
import javax.sip.header.ExpiresHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.HeaderFactory;
import javax.sip.header.MaxForwardsHeader;
import javax.sip.header.SupportedHeader;
import javax.sip.header.ToHeader;
import javax.sip.header.ViaHeader;
import javax.sip.header.WWWAuthenticateHeader;
import javax.sip.message.MessageFactory;
import javax.sip.message.Request;
import javax.sip.message.Response;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.ListIterator;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.microsoft.security.ntlm.impl.Algorithms.ASCII_ENCODING;
import static org.microsoft.security.ntlm.impl.Algorithms.bytesToString;

/**
 * This class is example of connecting to MS OCS (Office Communicator Server) aka Lync
 *
 * This class uses NTLM authentication to login to OCS
 *
 * @author M. Ranganathan
 * @author Kathleen McCallum
 */

public class LyncConnector implements SipListener {
    private static final Logger log = Logger.getLogger("ntlm-examples-sip.LyncConnector");

    private static SipProvider sipProvider;
    private static AddressFactory addressFactory;
    private static MessageFactory messageFactory;
    private static HeaderFactory headerFactory;
    private static SipStack sipStack;
    long invco = 1;


    private static String PROPERTIES_FILE_NAME = "ntlm-example.properties";

    private static String NTLM_HOSTNAME;
    private static String NTLM_DOMAIN;

    private static String sipHostname;
    private static String sipDomain;
    private static String sipServer;

    private static String defaultUsername;
    private static String defaultPassword;

    private static String TRANSPORT_STRING;

    private static String sipTag = "12345";


    private static final int SipAuthVersion = 4;

    /*
    defined in [MS-SIPAE], not obvious
     */
    private static final int MAGIC_SEQ_NUM = 100;

    /**
     * Namespace for fcacfb03-8a73-46ef-91b1-e5ebeeaba4fe
     * as defined in [MS-SIP] 3.2.3.1 User Agent Initialization
     */
    private static final byte[] SIP_UUID_NAMESPACE = Algorithms.stringToBytes(
            "03 fb ac fc 73 8a ef 46 91 b1 e5 eb ee ab a4 fe"
    );


/*
 * epid note:
 * pidgin uses the following to calculate epid:
 * Use last 6 bytes of sha1(sip_uri:hostname:ip_address)
 *
 * To calculate instances:
 * SIPE_PUB_DEVICE - the same as first 4 bytes of epid
 * SIPE_PUB_STATE_MACHINE - 0x3_epid_
 * SIPE_PUB_STATE_USER - 0x20000000
 * SIPE_PUB_STATE_CALENDAR - 0x4_epid_
 * SIPE_PUB_STATE_CALENDAR_OOF - 0x5_epid_
 * SIPE_PUB_CALENDAR_DATA, SIPE_PUB_NOTE_OOF - 0x4_last6bytesof(sha1(email))_
 */
    static final String DEFAULT_SIP_EPID = "d3665ff3bd3e";

    private final UserInfo defaultUser = new UserInfo(defaultUsername, defaultPassword, DEFAULT_SIP_EPID);

    // NTLM
    private String realm;
    private String targetname;

    @BeforeClass
    public static void loadProperties() throws Exception {
        Properties properties = new Properties();
        File propertiesFile = new File(PROPERTIES_FILE_NAME);
        if (!propertiesFile.isFile()) {
            log.error("Properties file not exist: " + propertiesFile.getCanonicalPath());
            File examplesPropertiesFile = new File(propertiesFile + ".example");
            if (!examplesPropertiesFile.exists()) {
                PrintWriter out = new PrintWriter(new FileWriter(examplesPropertiesFile));
                out.println("# Local computer name - used for NTLM authentication. Seems that this field is ignored during NTLM");
                out.println("ntlm.hostname=localhost");
                out.println();
                out.println("# NTLM domain - generally your windows domain");
                out.println("ntlm.domain=123456");
                out.println();
                out.println("# User");
                out.println("username.default=user1");
                out.println();
                out.println("# Password");
                out.println("userpassword.default=password1");
                out.println();
                out.println("# Local host name that is assignable from sip server");
                out.println("sip.local.hostname=your.organization.com");
                out.println();
                out.println("# Sip Domain is generally your windows domain (long-form)");
                out.println("sip.domain=your.organization.com");
                out.println();
                out.println("# Sip server is URL of your OCS/Lync server. This can be loaded from DNS: ");
                out.println("#   see _sipinternaltls._tcp.<domain>, _sipinternal._tcp.<domain>, _sip._tls.<domain>, _sip._tcp.<domain> records");
                out.println("sip.server=lyncorocs.your.organization.com");
                out.println();
                out.println("# Sip transport. TCP or TLS ");
                out.println("sip.transport=tcp");
                out.close();
            }
            throw new IllegalArgumentException("Properties file not exist: " + propertiesFile.getCanonicalPath());
        }
        FileReader fileReader = new FileReader(propertiesFile);
        properties.load(fileReader);
        fileReader.close();

        NTLM_HOSTNAME = properties.getProperty("ntlm.hostname");
        NTLM_DOMAIN = properties.getProperty("ntlm.domain");
        defaultUsername = properties.getProperty("username.default");
        defaultPassword = properties.getProperty("userpassword.default");

        sipHostname = properties.getProperty("sip.local.hostname");
//        sipHostname = InetAddress.getLocalHost().getCanonicalHostName();
        sipDomain = properties.getProperty("sip.domain");
        sipServer = properties.getProperty("sip.server");

        TRANSPORT_STRING = properties.getProperty("sip.transport");
    }

    @Test
    public void doLyncTest() throws Exception {
        login(defaultUser);

        invco = 1;
        listContacts(defaultUser);
    }

    /**
     * (Legacy since ACL was replaced by container model)
     *
     * [MS-SIP] 3.7.4.1 Subscribing to the Contact/Group List
     *          3.7.5.2 Receiving the Contact List from the Server


     *
     * @param userInfo user info
     * @throws Exception any error
     */
    private void listContacts(UserInfo userInfo) throws Exception {
        Request request = userInfo.createSubscribeRequest("vnd-microsoft-roaming-contacts");

        AcceptHeader acceptHeader = headerFactory.createAcceptHeader("application", "vnd-microsoft-roaming-contacts+xml");
        SupportedHeader supportedHeader = headerFactory.createSupportedHeader("com.microsoft.autoextend, ms-benotify, ms-piggyback-first-notify");
        request.setHeader(acceptHeader);
        request.setHeader(supportedHeader);

        Response sipServletResponse = userInfo.sendNtlmRequest();
        Assert.assertEquals(200, sipServletResponse.getStatusCode());
        Object content = userInfo.getResponse().getContent();
        log.trace("Content: " + content);

        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new ByteArrayInputStream((byte[]) content));
        //when XMLStreamReader is created, it is positioned at START_DOCUMENT event.
        //check if there are  more events  in  the input stream
        while(xmlStreamReader.hasNext()) {
            int eventType =  xmlStreamReader.next();
            //printEventType(eventType);
            //these functions  prints the information about the  particular event by calling relevant function
            switch  (eventType) {
                case XMLEvent.START_ELEMENT:
                    log.info("Element: " + xmlStreamReader.getName());
                    for (int i = 0; i < xmlStreamReader.getAttributeCount(); i++) {
                        log.info("    " + xmlStreamReader.getAttributeName(i) + " = " + xmlStreamReader.getAttributeValue(i));
                    }
                    break;
            }
        }

    }


    public void login(UserInfo defaultUser) throws Exception {
        sendInitialRequest(defaultUser);
        Assert.assertEquals(401, defaultUser.getResponse().getStatusCode());
        sendAuthenticationNtlmRequest1(defaultUser);
        Assert.assertEquals(401, defaultUser.getResponse().getStatusCode());
        sendAuthenticationNtlmRequest2(defaultUser);
        Assert.assertEquals(200, defaultUser.getResponse().getStatusCode());
    }

    private void sendInitialRequest(UserInfo userInfo) throws Exception {
        userInfo.createNewRequest("REGISTER", false);

        Response sipServletResponse = userInfo.sendRequest();
        Assert.assertEquals(401, sipServletResponse.getStatusCode());
    }

    private void sendAuthenticationNtlmRequest1(UserInfo userInfo) throws Exception {
        @SuppressWarnings({"unchecked"})
        ListIterator<WWWAuthenticateHeader> authenticateHeadersIter = userInfo.getResponse().getHeaders(WWWAuthenticateHeader.NAME);
        Map<String, WWWAuthenticateHeader> authenticateHeaders = new HashMap<String, WWWAuthenticateHeader>();
        while (authenticateHeadersIter.hasNext()) {
            WWWAuthenticateHeader authenticateHeader = authenticateHeadersIter.next();
            authenticateHeaders.put(authenticateHeader.getScheme(), authenticateHeader);
        }
        WWWAuthenticateHeader ntlmAuthenticateHeader = authenticateHeaders.get("NTLM");
        final String realm = ntlmAuthenticateHeader.getRealm();
        final String targetname = ntlmAuthenticateHeader.getParameter("targetname");


        Request sipServletRequest = userInfo.createNextNewRequest();
        AuthorizationHeader authorizationHeader = headerFactory.createAuthorizationHeader("NTLM");
        authorizationHeader.setQop("auth");
        authorizationHeader.setRealm(realm);
        authorizationHeader.setParameter("targetname", '"' + targetname + '"');
        authorizationHeader.setParameter("gssapi-data", "\"\"");
        authorizationHeader.setParameter("version", "" + SipAuthVersion);

//                "NTLM qop=\"auth\", realm=\"" + realm + "\", targetname=\"" + targetname + "\", "
//                        + "gssapi-data=\"\", version=" + SipAuthVersion);
        sipServletRequest.setHeader(authorizationHeader);


        Response sipServletResponse = userInfo.sendRequest();
        Assert.assertEquals(401, sipServletResponse.getStatusCode());
    }

    private void sendAuthenticationNtlmRequest2(UserInfo userInfo) throws Exception {
        NtlmSession ntlmSession = userInfo.getNtlmSession();

        Response response = userInfo.getResponse();
        WWWAuthenticateHeader ntlmAuthenticateHeader = (WWWAuthenticateHeader) response.getHeader(WWWAuthenticateHeader.NAME);
        userInfo.opaque = ntlmAuthenticateHeader.getOpaque();
        userInfo.cnum = 1;
        final String gssapiDataString = ntlmAuthenticateHeader.getParameter("gssapi-data");
        final byte[] gssapiData = Algorithms.decodeBase64(gssapiDataString);

        realm = ntlmAuthenticateHeader.getRealm();
        targetname = ntlmAuthenticateHeader.getParameter("targetname");

        ntlmSession.processChallengeMessage(gssapiData);
        String newGssapiData = Algorithms.encodeBase64(ntlmSession.generateAuthenticateMessage());

        //
        // Event
        //
        userInfo.createNextNewRequest();

        AuthorizationHeader authorizationHeader = headerFactory.createAuthorizationHeader("NTLM");

        authorizationHeader.setParameter("gssapi-data", '"' + newGssapiData + '"');
        authorizationHeader.setParameter("version", "" + SipAuthVersion);
        Response newResponse = userInfo.sendNtlmRequest(authorizationHeader);
        Assert.assertEquals(200, newResponse.getStatusCode());
    }

    private String nonNull(String toTag) {
        return toTag == null ? "" : toTag;
    }


    /*
[MS-SIPRE] 3.2.3.1 User Agent Initialization
     */
    static String calculateSipUuid(String epid) {
        byte[] bytes = Algorithms.concat(SIP_UUID_NAMESPACE, epid.getBytes(Algorithms.ASCII_ENCODING));
        byte[] sha1 = Algorithms.calculateSHA1(bytes);
        char[] out = new char[16*2+4];
        Algorithms.bytesToCharsReverse(sha1, 0, 4, out, 0); // time_low
        out[8] = '-';
        Algorithms.bytesToCharsReverse(sha1, 4, 2, out, 9); // time_mid
        out[13] = '-';

        /*
8. Set the four most significant bits, which are bits 12 through 15, of the time_hi_and_version
field to the 4-bit version number, as specified in [RFC4122] section 4.1.3. For name-based UUIDs
computed with the SHA-1 function, this sequence is 0101.
         */
        sha1[7] = (byte) (sha1[7] & 0xf | 0x50);
        Algorithms.bytesToCharsReverse(sha1, 6, 2, out, 14); // time_hi_and_version
        out[18] = '-';

        /*
10.Set the two most significant bits, which are bits 6 and 7, of the clock_seq_hi_and_reserved to
zero and 1, respectively.
         */
        sha1[8] = (byte) (sha1[8] & 0x3f | 0x80);
        Algorithms.bytesToChars(sha1, 8, 2, out, 19); // clock_seq_hi_and_reserved

        out[23] = '-';
        Algorithms.bytesToChars(sha1, 10, 6, out, 24);
        return new String(out);
    }



    public void processRequest(RequestEvent requestReceivedEvent) {
        Request request = requestReceivedEvent.getRequest();
        ServerTransaction serverTransactionId = requestReceivedEvent.getServerTransaction();

        log.trace(" >>> Request " + request.getMethod()
                + " received at " + sipStack.getStackName()
                + " with server transaction id " + serverTransactionId);

        // We are the UAC so the only request we get is the BYE.
        if (request.getMethod().equals(Request.BYE))
            processBye(request, serverTransactionId);
    }

    public void processBye(Request request, ServerTransaction serverTransactionId) {
        try {
            log.trace("shootist:  got a bye .");
            if (serverTransactionId == null) {
                log.trace("shootist:  null TID.");
                return;
            }
            Dialog dialog = serverTransactionId.getDialog();
            log.trace("Dialog State = " + dialog.getState());
            Response response = messageFactory.createResponse(200, request);
            serverTransactionId.sendResponse(response);
            log.trace("shootist:  Sending OK.");
            log.trace("Dialog State = " + dialog.getState());

        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(0);

        }
    }

    public void processResponse(ResponseEvent responseReceivedEvent) {
        log.trace("-------------------------------------------------------------------------------- <<< Got a response");
        Response response = responseReceivedEvent.getResponse();
        ClientTransaction tid = responseReceivedEvent.getClientTransaction();
        CSeqHeader cseq = (CSeqHeader) response.getHeader(CSeqHeader.NAME);

        log.trace("Response received : Status Code = " + response.getStatusCode() + " " + cseq);
        if (tid == null) {
            log.trace("Stray response -- dropping ");
            return;
        }
        log.trace("transaction state is " + tid.getState());
        Dialog dialog = tid.getDialog();
        log.trace("Transaction = " + tid + ", Dialog = " + dialog + (dialog == null ? "--" : tid.getDialog().getState()));

        try {
            if (response.getStatusCode() == Response.OK) {
/*
Right now we don't do invite

                if (cseq.getMethod().equals(Request.INVITE)) {
                    Dialog dialog = inviteTid.getDialog();
                    Request ackRequest = dialog.createAck( cseq.getSeqNumber() );
                    log.trace("Sending ACK");
                    dialog.sendAck(ackRequest);
                } else if (cseq.getMethod().equals(Request.CANCEL)) {
                    if (dialog.getState() == DialogState.CONFIRMED) {
                        // oops cancel went in too late. Need to hang up the
                        // dialog.
                        log.trace("Sending BYE -- cancel went in too late !!");
                        Request byeRequest = dialog.createRequest(Request.BYE);
                        ClientTransaction ct = sipProvider.getNewClientTransaction(byeRequest);
                        dialog.sendRequest(ct);
                    }
                }
*/
            }


            try {
                Object data = tid.getApplicationData();
                UserInfo userInfo = (UserInfo) data;
                log.trace("Responce received for user:" + userInfo);
                userInfo.onResponce(response);
            } catch (Exception e) {
                log.error("Error processing request", e);
            }

        } catch (Exception ex) {
            log.error("Process response error", ex);
        }

    }

    public void processTimeout(javax.sip.TimeoutEvent timeoutEvent) {
        log.trace("Transaction Time out");
    }


    @Before
    public void init() {
        SipFactory sipFactory = SipFactory.getInstance();
        sipFactory.setPathName("gov.nist");

        Properties properties = new Properties();
        properties.setProperty("javax.sip.OUTBOUND_PROXY", sipServer + "/" + TRANSPORT_STRING);
        properties.setProperty("javax.sip.STACK_NAME", "shootistAuth");
        properties.setProperty("gov.nist.javax.sip.MAX_MESSAGE_SIZE", "1048576");
        properties.setProperty("gov.nist.javax.sip.DEBUG_LOG", "shootistAuthdebug.txt");
        properties.setProperty("gov.nist.javax.sip.SERVER_LOG", "shootistAuthlog.txt");
//        properties.setProperty("gov.nist.javax.sip.TRACE_LEVEL", "64");
        properties.setProperty("gov.nist.javax.sip.TRACE_LEVEL", "LOG4J");
        // Drop the client connection after we are done with the transaction.
        properties.setProperty("gov.nist.javax.sip.CACHE_CLIENT_CONNECTIONS", "false");
        properties.setProperty("gov.nist.javax.sip.NETWORK_LAYER", TestSslNetworkLayer.class.getName());



        try {
            // Create SipStack object
            sipStack = sipFactory.createSipStack(properties);
            log.trace("createSipStack " + sipStack);
        } catch (PeerUnavailableException e) {
            // could not find gov.nist.jain.protocol.ip.sip.SipStackImpl in the
            // classpath
            e.printStackTrace();
            System.err.println(e.getMessage());
            System.exit(0);
        }
        try {
            headerFactory = sipFactory.createHeaderFactory();
            addressFactory = sipFactory.createAddressFactory();
            messageFactory = sipFactory.createMessageFactory();
            int port = TRANSPORT_STRING.equalsIgnoreCase("tcp") ? 5060 : 5061;
            ListeningPoint listeningPoint = sipStack.createListeningPoint(sipHostname, port, TRANSPORT_STRING);
            sipProvider = sipStack.createSipProvider(listeningPoint);
            sipProvider.addSipListener(this);

        } catch (PeerUnavailableException e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
            System.exit(0);
        } catch (Exception e) {
            log.trace("Creating Listener Points");
            log.trace(e.getMessage());
            e.printStackTrace();
        }

    }

    public void processIOException(IOExceptionEvent exceptionEvent) {
        log.trace("IOException happened for "
                + exceptionEvent.getHost() + " port = "
                + exceptionEvent.getPort());

    }

    public void processTransactionTerminated(
            TransactionTerminatedEvent transactionTerminatedEvent) {
        log.trace("Transaction terminated event recieved");
    }

    public void processDialogTerminated(
            DialogTerminatedEvent dialogTerminatedEvent) {
        log.trace("dialogTerminatedEvent");

    }



    private final class UserInfo {
        private String username;
        private String epid;
        private String sipInstance;

        private NtlmSession ntlmSession;
        private CyclicBarrier cyclicBarrier = new CyclicBarrier(2);
//        SipSession sipSession;
        private Request request;
        private Response response;
        private int cnum;
        private String opaque;
        private ClientTransaction transaction;
        private Dialog dialog;


        UserInfo(String username, String password, String epid) {
            this.username = username;
            this.epid = epid;
            this.sipInstance = calculateSipUuid(epid);
            NtlmAuthenticator ntlmAuthentication = new NtlmAuthenticator(NtlmAuthenticator.NtlmVersion.ntlmv2, NtlmAuthenticator.ConnectionType.connectionless
                    , NTLM_HOSTNAME, NTLM_DOMAIN, username, password);
            ntlmSession = ntlmAuthentication.createSession();
        }


        public Request createNextNewRequest() throws Exception {
//            sipServletRequest = sipFactory.createRequest(this.sipServletRequest, true);
            request = (Request) request.clone();

            // Create a new Cseq header
            CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(invco++, request.getMethod());
            request.setHeader(cSeqHeader);

            // Create the client transaction.
            transaction = sipProvider.getNewClientTransaction(request);
            transaction.setApplicationData(this);
            dialog = transaction.getDialog();

            return request;
        }

        public Request createNewRequest(String method, boolean addUsername) throws Exception {
            // create >From Header
            SipURI fromAddress = addressFactory.createSipURI(username, sipDomain);
            Address fromNameAddress = addressFactory.createAddress(fromAddress);
            FromHeader fromHeader = headerFactory.createFromHeader(fromNameAddress, sipTag);
            // epid is defined in [MS-SIPRE]
            fromHeader.setParameter("epid", epid);

            // create To Header
            SipURI toAddress = addressFactory.createSipURI(username, sipDomain);
            Address toNameAddress = addressFactory.createAddress(toAddress);
            ToHeader toHeader = headerFactory.createToHeader(toNameAddress, null);

            // Create ViaHeaders
            ArrayList<ViaHeader> viaHeaders = new ArrayList<ViaHeader>();
            ViaHeader viaHeader = headerFactory.createViaHeader(sipHostname, sipProvider.getListeningPoint(TRANSPORT_STRING).getPort(), TRANSPORT_STRING, null);
            // add via headers
            viaHeaders.add(viaHeader);

            // create Request URI
            URI requestURI = addUsername ? addressFactory.createSipURI(username, sipDomain)
                    : addressFactory.createURI("sip:" + sipDomain);

            // Create a new CallId header
//            CallIdHeader callIdHeader = headerFactory.createCallIdHeader("wiItgvjFld");
            CallIdHeader callIdHeader = sipProvider.getNewCallId();

            // Create a new Cseq header
            CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(invco++, method);

            // Create a new MaxForwardsHeader
            MaxForwardsHeader maxForwards = headerFactory.createMaxForwardsHeader(70);

            // Create the request.
            request = messageFactory.createRequest(requestURI,
                    method, callIdHeader, cSeqHeader, fromHeader, toHeader,
                    viaHeaders, maxForwards);


            SipURI contactUrl = addressFactory.createSipURI(username, sipDomain);

            Address contactAddress = addressFactory.createAddress(contactUrl);
            ContactHeader contactHeader = headerFactory.createContactHeader(contactAddress);
            contactHeader.setParameter("proxy", "replace");
            contactHeader.setParameter("+sip.instance", "\"<urn:uuid:" + sipInstance + ">\"");

            request.addHeader(contactHeader);



            // Create the client transaction.
            transaction = sipProvider.getNewClientTransaction(request);
            transaction.setApplicationData(this);
            dialog = transaction.getDialog();

            return request;
        }

/*
        private Map<String, SipSession> subscribedEvents = new HashMap<String, SipSession>();
        public SipServletRequest createSubscribeRequest(String event) throws ServletParseException {
            createNewRequest("SUBSCRIBE");
            sipServletRequest.setHeader("Event", event);
            subscribedEvents.put(event, sipServletRequest.getSession());
            log.trace("Subscribe [" + username + "] to event: " + event);
            return sipServletRequest;
        }

        public void unsubscribeEvents() throws Exception {
            log.trace("Unsubscribe [" + username + "] from events: " + subscribedEvents.keySet());
            for (Map.Entry<String, SipSession> eventEntry : subscribedEvents.entrySet()) {
                String event = eventEntry.getKey();
                log.trace("Unsubscribe [" + username + "] from event: " + event);
                try {
                    SipSession sipSession = eventEntry.getValue();
                    sipServletRequest = sipSession.createRequest("SUBSCRIBE");
//                    createNewRequest("SUBSCRIBE");

                    sipServletRequest.addHeader("Route", sipServerUrl);
                    javax.servlet.sip.Address contactAddress = sipServletRequest.getAddressHeader("Contact");
//        contactAddress.setURI(sipFactory.createURI("sip:" + LOCALHOST_IP + ";transport=tcp"));
                    contactAddress.setParameter("proxy", "replace");
                    contactAddress.setParameter("+sip.instance", "\"<urn:uuid:" + sipInstance + ">\"");

                    // epid is defined in [MS-SIPRE]
//                    sipServletRequest.getFrom().setParameter("epid", epid);


                    sipServletRequest.addHeader("User-Agent", "UCCP/2.0.6362.189 OC/2.0.6362.189 (Microsoft Office Communicator)");


                    sipServletRequest.setHeader("Event", event);
                    sipServletRequest.setHeader("Expires", "0");
                    sendNtlmRequest();
                    sipSession.invalidate();
                    Assert.assertEquals(200, sipServletResponse.getStatus());
                } catch (Throwable e) {
                    log.error("Error unsubscribe [" + username + "] from event: " + event, e);
                }
            }
        }
*/

        public Response getResponse() {
            return response;
        }

        public Response sendRequest() throws Exception {
            response = null;
//            request.getSession().setAttribute(USER_INFO, this);
            resetBarrier();

            log.trace("---------------------------------------------------------------- >>>");
            // send the request out.
            transaction.sendRequest();
            log.trace("----------------------------------------------------------------");

            waitBarrier();
            return response;
        }

        public void resetBarrier() {
            cyclicBarrier.reset();
        }

        public void waitBarrier() throws InterruptedException, BrokenBarrierException, TimeoutException {
            cyclicBarrier.await(2, TimeUnit.SECONDS);
        }

        public Response sendNtlmRequest() throws Exception {
            AuthorizationHeader authorizationHeader = headerFactory.createAuthorizationHeader("NTLM");
            return sendNtlmRequest(authorizationHeader);
        }

        public Response sendNtlmRequest(AuthorizationHeader authorizationHeader) throws Exception {
            authorizationHeader.setOpaque(opaque);
            authorizationHeader.setQop("auth");
            authorizationHeader.setRealm(realm);
            authorizationHeader.setParameter("targetname", targetname);
            //noinspection ConstantConditions
            if (SipAuthVersion >= 4) {


            // Version 4
            String crand = Algorithms.bytesToString(Algorithms.nonce(4));

            authorizationHeader.setParameter("crand", crand);
            authorizationHeader.setParameter("cnum", "" + cnum);

            CallIdHeader callId = (CallIdHeader) request.getHeader(CallIdHeader.NAME);

            // CSeq: 3 REGISTER
            CSeqHeader cseqHeader = (CSeqHeader) request.getHeader(CSeqHeader.NAME);
            long cseq = cseqHeader.getSeqNumber();
            String cseqMethod = cseqHeader.getMethod();
            FromHeader from = (FromHeader) request.getHeader(FromHeader.NAME);
            URI fromString = from.getAddress().getURI();
            String fromTag = nonNull(from.getTag());

            ToHeader to = (ToHeader) request.getHeader(ToHeader.NAME);
            URI toString = to.getAddress().getURI();
            String toTag = nonNull(to.getTag());

            ExpiresHeader expiresHeader = (ExpiresHeader) request.getHeader(ExpiresHeader.NAME);
            String expires = expiresHeader == null ? "" : "" + expiresHeader.getExpires();

            String messageString = "<NTLM><" + crand + "><" + cnum + "><" + realm + "><" + targetname + "><" + callId.getCallId() + "><"
                    + cseq + "><" + cseqMethod + "><"
                    + fromString + "><" + fromTag + "><" + toString + "><" + toTag + "><><><" + expires + ">";

            log.trace("Message: " + messageString);

            ntlmSession.updateSequenceNumber(MAGIC_SEQ_NUM);
            String macData = bytesToString(ntlmSession.calculateMac(messageString.getBytes(ASCII_ENCODING)));

            authorizationHeader.setResponse(macData);

            cnum++;
            }
            request.setHeader(authorizationHeader);
            return sendRequest();
        }

        private Map<String, Dialog> subscribedEvents = new HashMap<String, Dialog>();
        public Request createSubscribeRequest(String event) throws Exception {
            createNewRequest("SUBSCRIBE", true);
            EventHeader eventHeader = headerFactory.createEventHeader(event);
            request.setHeader(eventHeader);
            subscribedEvents.put(event, dialog);
            log.trace("Subscribe [" + username + "] to event: " + event);
            return request;
        }


        public void onResponce(Response sipServletResponse) {
            log.trace("--- responce received");
            this.response = sipServletResponse;
            try {
                cyclicBarrier.await();
            } catch (Exception e) {
                log.error("Sync error", e);
            }
        }

        public NtlmSession getNtlmSession() {
            return ntlmSession;
        }

        @Override
        public String toString() {
            return "UserInfo{" + username + '}';
        }
    }



}
