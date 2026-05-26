defmodule Plausible.Ingestion.Event do
  @moduledoc """
  This module exposes the `build_and_buffer/1` function capable of
  turning %Plausible.Ingestion.Request{} into a series of events that in turn
  are uniformly either buffered in batches (to Clickhouse) or dropped
  (e.g. due to spam blocklist) from the processing pipeline.
  """
  use Plausible
  require Logger
  alias Plausible.Ingestion.Request
  alias Plausible.ClickhouseEventV2
  alias Plausible.Site.GateKeeper

  defstruct domain: nil,
            site: nil,
            clickhouse_event_attrs: %{},
            clickhouse_session_attrs: %{},
            clickhouse_event: nil,
            dropped?: false,
            drop_reason: nil,
            request: nil,
            salts: nil,
            changeset: nil

  @type drop_reason() ::
          :bot
          | :bot_agent
          | :china_ghost
          | :spam_referrer
          | GateKeeper.policy()
          | :invalid
          | :dc_ip
          | :site_ip_blocklist
          | :site_country_blocklist
          | :site_page_blocklist
          | :site_hostname_allowlist

  @type t() :: %__MODULE__{
          domain: String.t() | nil,
          site: %Plausible.Site{} | nil,
          clickhouse_event_attrs: map(),
          clickhouse_session_attrs: map(),
          clickhouse_event: %ClickhouseEventV2{} | nil,
          dropped?: boolean(),
          drop_reason: drop_reason(),
          request: Request.t(),
          salts: map(),
          changeset: %Ecto.Changeset{}
        }

  @spec build_and_buffer(Request.t()) :: {:ok, %{buffered: [t()], dropped: [t()]}}
  def build_and_buffer(%Request{domains: domains} = request) do
    processed_events =
      if spam_referrer?(request) do
        for domain <- domains, do: drop(new(domain, request), :spam_referrer)
      else
        Enum.reduce(domains, [], fn domain, acc ->
          case GateKeeper.check(domain) do
            {:allow, site} ->
              processed =
                domain
                |> new(site, request)
                |> process_unless_dropped(pipeline())

              [processed | acc]

            {:deny, reason} ->
              [drop(new(domain, request), reason) | acc]
          end
        end)
      end

    {dropped, buffered} = Enum.split_with(processed_events, & &1.dropped?)
    {:ok, %{dropped: dropped, buffered: buffered}}
  end

  @spec telemetry_event_buffered() :: [atom()]
  def telemetry_event_buffered() do
    [:plausible, :ingest, :event, :buffered]
  end

  @spec telemetry_event_dropped() :: [atom()]
  def telemetry_event_dropped() do
    [:plausible, :ingest, :event, :dropped]
  end

  def telemetry_pipeline_step_duration() do
    [:plausible, :ingest, :pipeline, :step]
  end

  @spec emit_telemetry_buffered(t()) :: :ok
  def emit_telemetry_buffered(event) do
    :telemetry.execute(telemetry_event_buffered(), %{}, %{
      domain: event.domain,
      request_timestamp: event.request.timestamp
    })
  end

  @spec emit_telemetry_dropped(t(), drop_reason()) :: :ok
  def emit_telemetry_dropped(event, reason) do
    :telemetry.execute(telemetry_event_dropped(), %{}, %{
      domain: event.domain,
      reason: reason,
      request_timestamp: event.request.timestamp
    })
  end

  defp pipeline() do
    [
      drop_datacenter_ip: &drop_datacenter_ip/1,
      drop_bot_agent: &drop_bot_agent/1,
      drop_shield_rule_hostname: &drop_shield_rule_hostname/1,
      drop_shield_rule_page: &drop_shield_rule_page/1,
      drop_shield_rule_ip: &drop_shield_rule_ip/1,
      put_geolocation: &put_geolocation/1,
      drop_china_ghost_traffic: &drop_china_ghost_traffic/1,
      drop_shield_rule_country: &drop_shield_rule_country/1,
      put_user_agent: &put_user_agent/1,
      put_basic_info: &put_basic_info/1,
      put_referrer: &put_referrer/1,
      put_utm_tags: &put_utm_tags/1,
      put_props: &put_props/1,
      put_revenue: &put_revenue/1,
      put_salts: &put_salts/1,
      put_user_id: &put_user_id/1,
      validate_clickhouse_event: &validate_clickhouse_event/1,
      register_session: &register_session/1,
      write_to_buffer: &write_to_buffer/1
    ]
  end

  defp process_unless_dropped(%__MODULE__{} = initial_event, pipeline) do
    Enum.reduce_while(pipeline, initial_event, fn {step_name, step_fn}, acc_event ->
      Plausible.PromEx.Plugins.PlausibleMetrics.measure_duration(
        telemetry_pipeline_step_duration(),
        fn -> execute_step(step_fn, acc_event) end,
        %{step: "#{step_name}"}
      )
    end)
  end

  defp execute_step(step_fn, acc_event) do
    case step_fn.(acc_event) do
      %__MODULE__{dropped?: true} = dropped -> {:halt, dropped}
      %__MODULE__{dropped?: false} = event -> {:cont, event}
    end
  end

  defp new(domain, request) do
    struct!(__MODULE__, domain: domain, request: request)
  end

  defp new(domain, site, request) do
    struct!(__MODULE__, domain: domain, site: site, request: request)
  end

  defp drop(%__MODULE__{} = event, reason, attrs \\ []) do
    fields =
      attrs
      |> Keyword.put(:dropped?, true)
      |> Keyword.put(:drop_reason, reason)

    emit_telemetry_dropped(event, reason)
    struct!(event, fields)
  end

  defp update_event_attrs(%__MODULE__{} = event, %{} = attrs) do
    struct!(event, clickhouse_event_attrs: Map.merge(event.clickhouse_event_attrs, attrs))
  end

  defp update_session_attrs(%__MODULE__{} = event, %{} = attrs) do
    struct!(event, clickhouse_session_attrs: Map.merge(event.clickhouse_session_attrs, attrs))
  end

  defp drop_datacenter_ip(%__MODULE__{} = event) do
    case event.request.ip_classification do
      "dc_ip" ->
        drop(event, :dc_ip)

      _any ->
        event
    end
  end

  @bot_patterns [
    # Major search engine crawlers
    "googlebot", "bingbot", "yandexbot", "baiduspider", "duckduckbot",
    "slurp", "sogou", "exabot", "ia_archiver", "archive.org_bot",
    # SEO / marketing tools
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "rogerbot",
    "screaming frog", "seobilitybot", "sistrix", "blexbot",
    "linkdexbot", "megaindex", "serpstatbot", "dataforseo",
    # Social media crawlers
    "facebookexternalhit", "twitterbot", "linkedinbot", "pinterestbot",
    "slackbot", "telegrambot", "whatsapp", "discordbot",
    # Headless browsers & automation
    "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
    "cypress", "webdriver", "chromedriver", "geckodriver",
    # HTTP libraries
    "python-requests", "python-urllib", "go-http-client", "java/",
    "apache-httpclient", "okhttp", "node-fetch", "axios/",
    "libwww-perl", "wget", "curl/", "httpie", "postman",
    "insomnia", "rest-client", "http_request", "guzzlehttp",
    "scrapy", "mechanize", "httpclient",
    # Generic bot / crawler / spider
    "bot/", "crawler", "spider", "scraper", "fetcher",
    # Monitoring & uptime
    "uptimerobot", "pingdom", "site24x7", "statuscake",
    "newrelicpinger", "datadoghq", "checkly",
    # Other
    "petalbot", "bytespider", "applebot", "amazonbot",
    "gptbot", "chatgpt-user", "claudebot", "anthropic-ai",
    "cohere-ai", "ccbot", "google-extended"
  ]

  defp drop_bot_agent(%__MODULE__{} = event) do
    ua = event.request.user_agent

    if is_binary(ua) and bot_user_agent?(String.downcase(ua)) do
      drop(event, :bot_agent)
    else
      event
    end
  end

  defp bot_user_agent?(ua_lower) do
    Enum.any?(@bot_patterns, fn pattern -> String.contains?(ua_lower, pattern) end)
  end

  defp drop_china_ghost_traffic(%__MODULE__{} = event) do
    country = Map.get(event.clickhouse_session_attrs, :country_code)
    event_name = event.request.event_name
    referrer = event.request.referrer

    if country == "CN" and event_name == "pageview" and (is_nil(referrer) or referrer == "") do
      drop(event, :china_ghost)
    else
      event
    end
  end

  defp drop_shield_rule_ip(%__MODULE__{} = event) do
    if Plausible.Shields.ip_blocked?(event.domain, event.request.remote_ip) do
      drop(event, :site_ip_blocklist)
    else
      event
    end
  end

  defp drop_shield_rule_hostname(%__MODULE__{} = event) do
    if Plausible.Shields.hostname_allowed?(event.domain, event.request.hostname) do
      event
    else
      drop(event, :site_hostname_allowlist)
    end
  end

  defp drop_shield_rule_page(%__MODULE__{} = event) do
    if Plausible.Shields.page_blocked?(event.domain, event.request.pathname) do
      drop(event, :site_page_blocklist)
    else
      event
    end
  end

  defp put_user_agent(%__MODULE__{} = event) do
    case parse_user_agent(event.request) do
      %UAInspector.Result{client: %UAInspector.Result.Client{name: "Headless Chrome"}} ->
        drop(event, :bot)

      %UAInspector.Result.Bot{} ->
        drop(event, :bot)

      %UAInspector.Result{} = user_agent ->
        update_session_attrs(event, %{
          operating_system: os_name(user_agent),
          operating_system_version: os_version(user_agent),
          browser: browser_name(user_agent),
          browser_version: browser_version(user_agent),
          screen_size: screen_size(user_agent)
        })

      _any ->
        event
    end
  end

  defp put_basic_info(%__MODULE__{} = event) do
    update_event_attrs(event, %{
      domain: event.domain,
      site_id: event.site.id,
      timestamp: event.request.timestamp,
      name: event.request.event_name,
      hostname: event.request.hostname,
      pathname: event.request.pathname
    })
  end

  defp put_referrer(%__MODULE__{} = event) do
    ref = parse_referrer(event.request.uri, event.request.referrer)

    update_session_attrs(event, %{
      referrer_source: get_referrer_source(event.request, ref),
      referrer: clean_referrer(ref)
    })
  end

  defp put_utm_tags(%__MODULE__{} = event) do
    query_params = event.request.query_params

    update_session_attrs(event, %{
      utm_medium: query_params["utm_medium"],
      utm_source: query_params["utm_source"],
      utm_campaign: query_params["utm_campaign"],
      utm_content: query_params["utm_content"],
      utm_term: query_params["utm_term"]
    })
  end

  defp put_geolocation(%__MODULE__{} = event) do
    case event.request.ip_classification do
      "anonymous_vpn_ip" ->
        update_session_attrs(event, %{country_code: "A1"})

      _any ->
        cf_country = event.request.cf_country
        cf_region_code = event.request.cf_region_code

        if is_binary(cf_country) and cf_country not in ["", "XX", "T1"] do
          # Best-effort GeoIP lookup for subdivision/city fallback.
          # CF gives us a more accurate country code, but GeoIP gives proper
          # ISO subdivision codes and numeric city geoname IDs.
          geoip = Plausible.Ingestion.Geolocation.lookup(event.request.remote_ip) || %{}

          # Try CF city name (normalising accents: "Montréal" → "Montreal"),
          # fall back to GeoIP city_geoname_id.
          city_geoname_id =
            cf_city_to_geoname_id(event.request.cf_city, cf_country) ||
              Map.get(geoip, :city_geoname_id)

          # Prefer GeoIP subdivision code (ISO format e.g. "CA-QC");
          # otherwise fall back to CF region code (e.g. "CA" => "US-CA").
          subdivision1 =
            Map.get(geoip, :subdivision1_code) ||
              cf_subdivision1_code(cf_country, cf_region_code)

          result = %{
            country_code: cf_country,
            subdivision1_code: subdivision1,
            subdivision2_code: Map.get(geoip, :subdivision2_code),
            city_geoname_id: city_geoname_id
          }

          maybe_log_geolocation_resolution(event, :cloudflare_fallback, result,
            geoip_subdivision1_code: Map.get(geoip, :subdivision1_code),
            geoip_city_geoname_id: Map.get(geoip, :city_geoname_id),
            cf_region_code: cf_region_code
          )

          event
          |> update_session_attrs(result)
          |> inject_cf_geo_props()
        else
          result = Plausible.Ingestion.Geolocation.lookup(event.request.remote_ip) || %{}
          maybe_log_geolocation_resolution(event, :geoip_only, result)
          update_session_attrs(event, result)
        end
    end
  end

  # Strip combining diacritical marks (accents) so that "Montréal" matches
  # the geonames entry "Montreal".
  defp strip_accents(str) do
    str
    |> :unicode.characters_to_nfd_binary()
    |> String.replace(~r/\p{M}/u, "")
  end

  defp cf_city_to_geoname_id(nil, _country), do: nil
  defp cf_city_to_geoname_id("", _country), do: nil

  defp cf_city_to_geoname_id(city_name, country_code) do
    case Location.get_city(city_name, country_code) do
      %{id: id} ->
        id

      nil ->
        # Retry with accents stripped: "Montréal" → "Montreal"
        normalized = strip_accents(city_name)

        case Location.get_city(normalized, country_code) do
          %{id: id} -> id
          nil -> nil
        end
    end
  end

  defp cf_subdivision1_code(country_code, region_code)
       when is_binary(country_code) and is_binary(region_code) do
    country = String.upcase(String.trim(country_code))
    region = String.upcase(String.trim(region_code))

    cond do
      country == "" or region == "" ->
        nil

      String.starts_with?(region, country <> "-") ->
        region

      true ->
        country <> "-" <> region
    end
  end

  defp cf_subdivision1_code(_, _), do: nil

  defp maybe_log_geolocation_resolution(event, source, result, extra \\ []) do
    if geo_debug_logging?() do
      Logger.info(
        "geo_debug geolocation_resolution=" <>
          inspect(%{
            source: source,
            remote_ip: event.request.remote_ip,
            cf_country: event.request.cf_country,
            cf_region: event.request.cf_region,
            cf_city: event.request.cf_city,
            result_country_code: Map.get(result, :country_code),
            result_subdivision1_code: Map.get(result, :subdivision1_code),
            result_subdivision2_code: Map.get(result, :subdivision2_code),
            result_city_geoname_id: Map.get(result, :city_geoname_id),
            extra: Map.new(extra)
          })
      )
    end
  end

  defp geo_debug_logging? do
    Application.get_env(:plausible, :geo_debug_logging, false)
  end

  defp inject_cf_geo_props(%__MODULE__{} = event) do
    cf_city = event.request.cf_city
    cf_region = event.request.cf_region

    # Always inject CF city/region as custom props so the raw CF data
    # is preserved even if the geoname lookup failed
    cf_props =
      %{}
      |> maybe_put("cf_city", cf_city)
      |> maybe_put("cf_region", cf_region)

    if map_size(cf_props) > 0 do
      existing_keys = Map.get(event.clickhouse_event_attrs, :"meta.key", [])
      existing_vals = Map.get(event.clickhouse_event_attrs, :"meta.value", [])

      {new_keys, new_vals} = Enum.unzip(cf_props)

      update_event_attrs(event, %{
        "meta.key": existing_keys ++ new_keys,
        "meta.value": existing_vals ++ new_vals
      })
    else
      event
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp drop_shield_rule_country(
         %__MODULE__{domain: domain, clickhouse_session_attrs: %{country_code: cc}} = event
       )
       when is_binary(domain) and is_binary(cc) do
    if Plausible.Shields.country_blocked?(domain, cc) do
      drop(event, :site_country_blocklist)
    else
      event
    end
  end

  defp drop_shield_rule_country(%__MODULE__{} = event), do: event

  defp put_props(%__MODULE__{request: %{props: %{} = props}} = event) do
    # defensive: ensuring the keys/values are always in the same order
    {keys, values} = Enum.unzip(props)

    update_event_attrs(event, %{
      "meta.key": keys,
      "meta.value": values
    })
  end

  defp put_props(%__MODULE__{} = event), do: event

  defp put_revenue(event) do
    on_ee do
      attrs = Plausible.Ingestion.Event.Revenue.get_revenue_attrs(event)
      update_event_attrs(event, attrs)
    else
      event
    end
  end

  defp put_salts(%__MODULE__{} = event) do
    %{event | salts: Plausible.Session.Salts.fetch()}
  end

  defp put_user_id(%__MODULE__{} = event) do
    update_event_attrs(event, %{
      user_id:
        generate_user_id(
          event.request,
          event.domain,
          event.clickhouse_event_attrs.hostname,
          event.salts.current
        )
    })
  end

  defp validate_clickhouse_event(%__MODULE__{} = event) do
    clickhouse_event =
      event
      |> Map.fetch!(:clickhouse_event_attrs)
      |> ClickhouseEventV2.new()

    case Ecto.Changeset.apply_action(clickhouse_event, nil) do
      {:ok, valid_clickhouse_event} ->
        %{event | clickhouse_event: valid_clickhouse_event}

      {:error, changeset} ->
        drop(event, :invalid, changeset: changeset)
    end
  end

  defp register_session(%__MODULE__{} = event) do
    previous_user_id =
      generate_user_id(
        event.request,
        event.domain,
        event.clickhouse_event.hostname,
        event.salts.previous
      )

    session =
      Plausible.Session.CacheStore.on_event(
        event.clickhouse_event,
        event.clickhouse_session_attrs,
        previous_user_id
      )

    %{
      event
      | clickhouse_event: ClickhouseEventV2.merge_session(event.clickhouse_event, session)
    }
  end

  defp write_to_buffer(%__MODULE__{clickhouse_event: clickhouse_event} = event) do
    {:ok, _} = Plausible.Event.WriteBuffer.insert(clickhouse_event)
    emit_telemetry_buffered(event)
    event
  end

  defp parse_referrer(_uri, _referrer_str = nil), do: nil

  defp parse_referrer(uri, referrer_str) do
    referrer_uri = URI.parse(referrer_str)

    if Request.sanitize_hostname(referrer_uri.host) !== Request.sanitize_hostname(uri.host) &&
         referrer_uri.host !== "localhost" do
      RefInspector.parse(referrer_str)
    end
  end

  defp get_referrer_source(request, ref) do
    source =
      request.query_params["utm_source"] ||
        request.query_params["source"] ||
        request.query_params["ref"]

    source || PlausibleWeb.RefInspector.parse(ref)
  end

  defp clean_referrer(nil), do: nil

  defp clean_referrer(ref) do
    uri = URI.parse(ref.referer)

    if PlausibleWeb.RefInspector.right_uri?(uri) do
      PlausibleWeb.RefInspector.format_referrer(uri)
    end
  end

  defp parse_user_agent(%Request{user_agent: user_agent}) when is_binary(user_agent) do
    Plausible.Cache.Adapter.get(:user_agents, user_agent, fn ->
      UAInspector.parse(user_agent)
    end)
  end

  defp parse_user_agent(request), do: request

  defp browser_name(ua) do
    case ua.client do
      :unknown -> ""
      %UAInspector.Result.Client{name: "Mobile Safari"} -> "Safari"
      %UAInspector.Result.Client{name: "Chrome Mobile"} -> "Chrome"
      %UAInspector.Result.Client{name: "Chrome Mobile iOS"} -> "Chrome"
      %UAInspector.Result.Client{name: "Firefox Mobile"} -> "Firefox"
      %UAInspector.Result.Client{name: "Firefox Mobile iOS"} -> "Firefox"
      %UAInspector.Result.Client{name: "Opera Mobile"} -> "Opera"
      %UAInspector.Result.Client{name: "Opera Mini"} -> "Opera"
      %UAInspector.Result.Client{name: "Opera Mini iOS"} -> "Opera"
      %UAInspector.Result.Client{name: "Yandex Browser Lite"} -> "Yandex Browser"
      %UAInspector.Result.Client{name: "Chrome Webview"} -> "Mobile App"
      %UAInspector.Result.Client{type: "mobile app"} -> "Mobile App"
      client -> client.name
    end
  end

  @mobile_types [
    "smartphone",
    "feature phone",
    "portable media player",
    "phablet",
    "wearable",
    "camera"
  ]
  @tablet_types ["car browser", "tablet"]
  @desktop_types ["tv", "console", "desktop"]
  alias UAInspector.Result.Device

  defp screen_size(ua) do
    case ua.device do
      %Device{type: t} when t in @mobile_types ->
        "Mobile"

      %Device{type: t} when t in @tablet_types ->
        "Tablet"

      %Device{type: t} when t in @desktop_types ->
        "Desktop"

      %Device{type: :unknown} ->
        nil

      %Device{type: type} ->
        Sentry.capture_message("Could not determine device type from UAInspector",
          extra: %{type: type}
        )

        nil

      _ ->
        nil
    end
  end

  defp browser_version(ua) do
    case ua.client do
      :unknown -> ""
      %UAInspector.Result.Client{type: "mobile app"} -> ""
      client -> major_minor(client.version)
    end
  end

  defp os_name(ua) do
    case ua.os do
      :unknown -> ""
      os -> os.name
    end
  end

  defp os_version(ua) do
    case ua.os do
      :unknown -> ""
      os -> major_minor(os.version)
    end
  end

  defp major_minor(version) do
    case version do
      :unknown ->
        ""

      version ->
        version
        |> String.split(".")
        |> Enum.take(2)
        |> Enum.join(".")
    end
  end

  defp generate_user_id(request, domain, hostname, salt) do
    cond do
      is_nil(salt) ->
        nil

      is_nil(domain) ->
        nil

      true ->
        user_agent = request.user_agent || ""
        root_domain = get_root_domain(hostname)

        SipHash.hash!(salt, user_agent <> request.remote_ip <> domain <> root_domain)
    end
  end

  defp get_root_domain(nil), do: "(none)"

  defp get_root_domain(hostname) do
    case :inet.parse_ipv4_address(String.to_charlist(hostname)) do
      {:ok, _} ->
        hostname

      {:error, :einval} ->
        PublicSuffix.registrable_domain(hostname) || hostname
    end
  end

  defp spam_referrer?(%Request{referrer: referrer}) when is_binary(referrer) do
    URI.parse(referrer).host
    |> Request.sanitize_hostname()
    |> ReferrerBlocklist.is_spammer?()
  end

  defp spam_referrer?(_), do: false
end
