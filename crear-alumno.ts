import { createClient } from 'npm:@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const admin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    )

    // 1) Quién está llamando
    const token = (req.headers.get('Authorization') ?? '').replace('Bearer ', '')
    const { data: quien, error: errQuien } = await admin.auth.getUser(token)
    if (errQuien || !quien.user) return json({ error: 'No autorizado' }, 401)

    // 2) Tiene que ser profe
    const { data: perfil } = await admin
      .from('profiles')
      .select('rol')
      .eq('id', quien.user.id)
      .single()
    if (!perfil || perfil.rol !== 'profe') {
      return json({ error: 'Solo el profe puede dar de alta alumnos' }, 403)
    }

    // 3) Crear el alumno
    const { email, password, nombre } = await req.json()
    if (!email || !password || String(password).length < 6) {
      return json({ error: 'Mail y contraseña (mínimo 6 caracteres) son obligatorios' }, 400)
    }
    const { data, error } = await admin.auth.admin.createUser({
      email: String(email).trim(),
      password: String(password),
      email_confirm: true,
      user_metadata: { nombre: String(nombre ?? '').trim() },
    })
    if (error) return json({ error: error.message }, 400)
    return json({ id: data.user.id, email: data.user.email })
  } catch (e) {
    return json({ error: String(e) }, 500)
  }
})
