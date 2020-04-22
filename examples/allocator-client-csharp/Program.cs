using System;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using Grpc.Core;
using Grpc.Core.Logging;
using V1Alpha1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using Grpc.Net.Client;
using Microsoft.Extensions.Logging;

namespace AllocatorClient
{
    class Program
    {
        //private static TextWriterLogger _logger;

        static async Task Main(string[] args)
        {
            //Environment.SetEnvironmentVariable("GRPC_DNS_RESOLVER", "native"); // Necessary in nuget version 1.1.0 to work around bug in code
            //AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
            //_logger.Info("START");
            //GrpcEnvironment.SetLogger(_logger);

            string baseAddress = "34.82.82.7";
            string serverCa = File.ReadAllText("tls.crt");
            string clientKey = File.ReadAllText("client.key");
            string clientCert = File.ReadAllText("client.crt");

            var creds = new SslCredentials(serverCa, new KeyCertificatePair(clientKey, clientCert));
            var channel = new Channel(baseAddress, 443, creds);
            //var client = new AllocationService.AllocationServiceClient(channel);
            var x509Cert = new X509Certificate2("client.pfx", "123");
            var client = CreateClientWithCert("https://" + baseAddress + ":443", x509Cert, creds);

            //var deadline = DateTime.UtcNow.AddSeconds(5);
            //await channel.ConnectAsync(deadline);
            
            try {
                var response = await client.PostAllocateAsync(new AllocationRequest {Namespace = "Default"});
                Console.Write(response.State.ToString());
            } 
            catch(RpcException e)
            {
                Console.WriteLine($"gRPC error: {e.Status.Detail}");
                Console.WriteLine($"{e}");
            }
            catch 
            {
                Console.WriteLine($"Unexpected error calling agones-allocator");
                throw;
            }

            await channel.ShutdownAsync();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        public static AllocationService.AllocationServiceClient CreateClientWithCert(
            string baseAddress,
            X509Certificate2 certificate,
            SslCredentials creds)
        {

            var loggerFactory = LoggerFactory.Create(logging =>
            {
                logging.AddConsole();
                logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
            });

            // Add client cert to the handler
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(certificate);
            handler.ServerCertificateCustomValidationCallback = 
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

            // Create the gRPC channel
            var channel = GrpcChannel.ForAddress(baseAddress, new GrpcChannelOptions
            {
                HttpClient = new HttpClient(handler),
                LoggerFactory = loggerFactory,
                //Credentials = creds,
                ThrowOperationCanceledOnCancellation = true,
            });

            return new AllocationService.AllocationServiceClient(channel);
        }
    }
}
