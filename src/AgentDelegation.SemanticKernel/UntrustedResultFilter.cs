using Microsoft.SemanticKernel;

namespace AgentDelegation.SemanticKernel;

/// <summary>
/// Wraps every function result in an <c>untrusted</c> marker before the model sees it.
/// Register with <c>services.AddSingleton&lt;IFunctionInvocationFilter, UntrustedResultFilter&gt;()</c>.
/// </summary>
public sealed class UntrustedResultFilter : IFunctionInvocationFilter
{
    /// <inheritdoc />
    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context, Func<FunctionInvocationContext, Task> next)
    {
        await next(context);

        string? raw = context.Result.GetValue<object>()?.ToString();
        context.Result = new FunctionResult(context.Result, UntrustedContent.Wrap(context.Function.Name, raw));
    }
}
