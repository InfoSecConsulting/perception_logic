from lib.xml_output_parser import parse_nmap_xml, parse_openvas_xml
from argparse import ArgumentParser


def main():
  parser = ArgumentParser('--nmap_xml, '
                          '--openvas_xml')

  parser.add_argument('--nmap_xml',
                      dest='nmap_xml',
                      type=str,
                      help='NMAP XML file to parse.')

  parser.add_argument('--openvas_xml',
                      dest='openvas_xml',
                      type=str,
                      help='OpenVAS XML file to parse.')

  args = parser.parse_args()
  nmap_xml = args.nmap_xml
  openvas_xml = args.openvas_xml

  if nmap_xml is not None:

    parse_nmap_xml(nmap_xml)

  if openvas_xml is not None:

    parse_openvas_xml(openvas_xml)

  if openvas_xml is None and nmap_xml is None:
    print('\nI need arguments.\n')
    parser.print_help()
    exit()


if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
