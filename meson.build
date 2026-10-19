project(
  'mws',
  meson_version : '>= 0.61.0',
  default_options : [
                  'prefix=/usr',
                  'sysconfdir=/etc',
                  'localstatedir=/var'],
  license : ['Apache-2.0'],
  version : '2.0.0',
)


go = find_program('go')

source_root = meson.project_source_root()

go_env = environment()
go_env.set('GOFLAGS', '')

custom_target('mws',
    output: 'mws',
    command: [go, '-C', source_root, 'build', '-buildmode=pie',
              '-o', meson.current_build_dir() / 'mws', './cmd/mws'],
    env: go_env,
    build_always_stale: true,
    build_by_default: true,
    install: true,
    install_dir: get_option('bindir'),
    install_mode: 'rwxr-xr-x')

test('go test', go,
  args: ['-C', source_root, 'test', './...'],
  env: go_env,
)

run_target('fmt', command: [go, '-C', source_root, 'fmt', './...'])
run_target('tidy', command: [go, '-C', source_root, 'mod', 'tidy'])
run_target('update', command: [go, '-C', source_root, 'get', '-v', '-u', './...'])
