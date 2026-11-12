// RQ4 case study: the refund flow as a Dapr workflow, with crashes and termination.
//
//   docker compose -f eval/dapr/docker-compose.yml up -d
//   dotnet run -c Release --project eval/dapr -- --out eval/dapr/results
//
// One executable, three roles. With no role it is the driver, which plays the user, starts the other two roles as
// child processes, runs every scenario and writes CSVs:
//   api     the payments tool behind the delegation gateway (and an unprotected copy for the baseline)
//   worker  the Dapr workflow worker: the support and payments agents' workflows and activities

using DaprCaseStudy;

return args switch
{
    ["api", .. string[] rest] => await PaymentsApi.RunAsync(rest),
    ["worker", .. string[] rest] => await Worker.RunAsync(rest),
    _ => await Driver.RunAsync(args),
};
