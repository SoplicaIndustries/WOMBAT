using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using WOMBAT.Tools;

namespace WOMBAT.Filters
{
    public class ActionFilters : IActionFilter
    {
        public void OnActionExecuted(ActionExecutedContext context)
        {
            
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue("ApiKey", out var extractedApiKey))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "API key was not provided"
                };
                return;
            }
            var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = config.GetValue<string>("ApiKey");
            var decodedKey = extractedApiKey; // <- do prezentacji EncodingTools.DecodeToken(extractedApiKey);
            if (!apiKey.Equals(decodedKey))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "Invalid API key"
                };
                return;
            }


        }
    }
}
